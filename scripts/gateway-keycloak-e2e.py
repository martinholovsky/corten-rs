#!/usr/bin/env python3
"""End-to-end test of corten-gateway against Keycloak, the reference identity
provider (docs/gates/gateway-proposal.md, Q4 revisited).

What it runs, all on loopback, all removed at the end:
  - Keycloak (pinned image, by digest) in a podman container, over HTTPS with a
    throwaway CA, configured through its admin API: a realm whose `acr` "phr" is
    level of authentication 2, a passkey flow whose WebAuthn step is a level-2
    condition, a password-only flow (the control), the gateway's client with
    private_key_jwt, and one user;
  - the corten-gateway binary (built from this tree), trusting that CA through
    SSL_CERT_FILE;
  - a mock program on a Unix socket that echoes the Authorization it receives;
  - a browser stand-in with a software WebAuthn authenticator (P-256, "none"
    attestation). Keycloak verifies its registration and assertions exactly as
    it would a hardware key's; only the browser is left out.

What it checks, in order:
  1. Control: a password-only sign-in. Keycloak asks to register a passkey
     first (the user's required action); the token then says acr "1", and the
     gateway refuses it with no session.
  2. A passkey sign-in: acr "phr"; the gateway gives a session, and the
     program receives a Corten token whose Ed25519 signature verifies against
     the key `corten-gateway check` reports, naming the Keycloak user.
  3. Logout, then the old cookie is refused.

With --deployed, everything runs in one podman pod instead: Keycloak, the
gateway built for Linux, and a Corten program (corten-std's `hello_listener`
demo) launched by corten-sandbox under its signed manifest, which grants a
`listen` socket on a volume shared with the gateway. The checks then also
show the program's answer naming the Keycloak user, the program's own log
of the authenticated request, and that the socket refuses a request that
skips the gateway (401). The Linux build runs in the pinned rust image; pass
--build-cache NAME to keep its target and registry in volumes NAME-target and
NAME-cargo between runs (otherwise they are removed with everything else).

Needs: podman, cargo, Python 3 with `cryptography`. Run from the repository
root:  scripts/gateway-keycloak-e2e.py [--deployed [--build-cache NAME]] [--keep-dir]
Exit 0 when every check passed, 1 on a failed check or a setup error.
"""

import argparse
import base64
import datetime
import hashlib
import html.parser
import http.client
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

IMAGE = "quay.io/keycloak/keycloak:26.8.2@sha256:4da21f9a53bcbac1026a0d654b740a81e98e5de4c45457076acc74b4d94b1551"
# The toolchain AGENTS.md pins for Linux checks; also the deployed containers' base.
RUST_IMAGE = "docker.io/library/rust:1.99.1-slim-bookworm@sha256:04f6411f947b7caf4b10bbf28ce2716cae46013e690403c371076db598b2951e"
REALM = "corten"
CLIENT = "corten-gateway"
USER = "alice"
# The admin and user passwords exist only inside the throwaway container.
ADMIN_PASSWORD = secrets.token_urlsafe(18)
USER_PASSWORD = secrets.token_urlsafe(18)
PHR_LEVEL = 2  # never 0 or 1: Keycloak gives level 1 to any sign-in with no level condition
MAX_BODY = 4 * 1024 * 1024  # largest response read
MAX_REDIRECTS = 15


class Failed(Exception):
    pass


def log(msg):
    print(f"gateway-keycloak-e2e: {msg}", file=sys.stderr, flush=True)


def check(cond, what):
    if not cond:
        raise Failed(what)
    log(f"ok: {what}")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------- certificates

def make_pki(d):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "corten e2e test CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    with open(os.path.join(d, "ca.crt"), "wb") as f:
        f.write(ca.public_bytes(pem))
    with open(os.path.join(d, "tls.crt"), "wb") as f:
        f.write(leaf.public_bytes(pem))
    key_path = os.path.join(d, "tls.key")
    with open(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return os.path.join(d, "ca.crt")


# ------------------------------------------------------------------ http client

class Response:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def header(self, name):
        return next((v for k, v in self.headers if k.lower() == name.lower()), None)

    def headers_named(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def text(self):
        return self.body.decode("utf-8", "replace")


class Browser:
    """Cookies per host:port, no automatic redirects, TLS against the test CA."""

    def __init__(self, ca, origins):
        self.ctx_ca = ca
        self.ctx = ssl.create_default_context(cafile=ca)
        self.jar = {}
        self.origins = set(origins)  # the only places this browser goes

    def request(self, method, url, form=None, headers=None):
        u = urllib.parse.urlsplit(url)
        if f"{u.scheme}://{u.hostname}:{u.port}" not in self.origins or u.username or u.password:
            raise Failed(f"refusing to follow {url!r}: not one of {sorted(self.origins)}")
        host = f"{u.hostname}:{u.port}"
        conn = http.client.HTTPSConnection(u.hostname, u.port, context=self.ctx, timeout=30)
        h = {"Host": host, "User-Agent": "corten-e2e"}
        h.update(headers or {})
        cookies = self.jar.get(host, {})
        if cookies and "Cookie" not in h:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        raw = r.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise Failed(f"{url}: response larger than {MAX_BODY} bytes")
        resp = Response(r.status, r.getheaders(), raw)
        conn.close()
        for sc in resp.headers_named("Set-Cookie"):
            name, _, rest = sc.partition("=")
            value = rest.split(";", 1)[0]
            attrs = sc.lower()
            jar = self.jar.setdefault(host, {})
            if "max-age=0" in attrs or "expires=thu, 01 jan 1970" in attrs or value == "":
                jar.pop(name.strip(), None)
            else:
                jar[name.strip()] = value
        return resp

    def follow(self, url, stop_prefix):
        """GETs and follows redirects until a non-redirect, or a Location starting with stop_prefix."""
        for _ in range(MAX_REDIRECTS):
            r = self.request("GET", url)
            loc = r.header("Location")
            if r.status not in (301, 302, 303, 307) or not loc:
                return url, r
            url = urllib.parse.urljoin(url, loc)
            if url.startswith(stop_prefix):
                return url, r
        raise Failed(f"too many redirects from {url}")


class Forms(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.cur = [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.cur = {"id": a.get("id"), "action": a.get("action"), "fields": {}}
            self.forms.append(self.cur)
        elif tag == "input" and self.cur is not None and a.get("name"):
            self.cur["fields"][a["name"]] = a.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None


def forms_of(page):
    p = Forms()
    p.feed(page)
    return p.forms


# ---------------------------------------------------------------- keycloak

class Keycloak:
    def __init__(self, work, ca, port=None, pod=None):
        self.port = port or free_port()
        self.base = f"https://localhost:{self.port}"
        self.name = f"corten-kc-e2e-{os.getpid()}"
        self.work, self.ca, self.pod = work, ca, pod
        self.ctx = ssl.create_default_context(cafile=ca)
        self.token = None

    def start(self):
        # In a pod, Keycloak listens on the published port number itself, so
        # the host's browser and the gateway inside the pod see one issuer URL.
        where = (["--pod", self.pod] if self.pod
                 else ["-p", f"127.0.0.1:{self.port}:8443"])
        port = [f"--https-port={self.port}"] if self.pod else []
        subprocess.run(
            ["podman", "run", "-d", "--rm", "--name", self.name, *where,
             "-v", f"{self.work}:/certs:ro,z",
             "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", f"KC_BOOTSTRAP_ADMIN_PASSWORD={ADMIN_PASSWORD}",
             IMAGE, "start-dev", "--https-certificate-file=/certs/tls.crt",
             "--https-certificate-key-file=/certs/tls.key", "--http-enabled=false", *port],
            check=True, stdout=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 180
        last = None
        while time.monotonic() < deadline:
            try:
                self.call("GET", "/realms/master/.well-known/openid-configuration", auth=False)
                return
            except (OSError, Failed) as e:
                last = e
                time.sleep(1)
        tail = subprocess.run(["podman", "logs", "--tail", "20", self.name], capture_output=True, text=True, check=False)
        raise Failed(f"Keycloak did not answer within 180 s (last error: {last!r}); its last log lines:\n" + (tail.stdout + tail.stderr)[-3000:])

    def stop(self):
        subprocess.run(["podman", "stop", "-t", "5", self.name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)

    def call(self, method, path, body=None, auth=True, form=None):
        conn = http.client.HTTPSConnection("localhost", self.port, context=self.ctx, timeout=30)
        h = {}
        data = None
        if auth:
            h["Authorization"] = f"Bearer {self.token}"
        if form is not None:
            data = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body)
            h["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        raw = r.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise Failed(f"Keycloak {path}: response larger than {MAX_BODY} bytes")
        loc = r.getheader("Location")
        conn.close()
        if r.status >= 300:
            raise Failed(f"Keycloak {method} {path}: {r.status} {raw[:300]!r}")
        return (json.loads(raw) if raw else None), loc

    def login_admin(self):
        tok, _ = self.call("POST", "/realms/master/protocol/openid-connect/token", auth=False, form={
            "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": ADMIN_PASSWORD})
        self.token = tok["access_token"]

    def flow(self, alias, steps):
        """A top-level flow; steps are (provider, requirement) or (subflow alias, requirement, [steps], level)."""
        a = f"/admin/realms/{REALM}/authentication"
        self.call("POST", f"{a}/flows", {"alias": alias, "providerId": "basic-flow", "topLevel": True, "builtIn": False})
        self._steps(alias, steps)
        flows, _ = self.call("GET", f"{a}/flows")
        return next(f["id"] for f in flows if f["alias"] == alias)

    def _steps(self, parent, steps):
        a = f"/admin/realms/{REALM}/authentication"
        p = urllib.parse.quote(parent)
        for step in steps:
            if len(step) == 2:
                self.call("POST", f"{a}/flows/{p}/executions/execution", {"provider": step[0]})
            else:
                self.call("POST", f"{a}/flows/{p}/executions/flow",
                          {"alias": step[0], "type": "basic-flow", "provider": "registration-page-form", "description": ""})
            execs, _ = self.call("GET", f"{a}/flows/{p}/executions")
            e = [x for x in execs if x["level"] == 0][-1]
            e["requirement"] = step[1]
            self.call("PUT", f"{a}/flows/{p}/executions", e)
            if len(step) == 4:
                self._steps(step[0], step[2])
                inner, _ = self.call("GET", f"{a}/flows/{urllib.parse.quote(step[0])}/executions")
                cond = next(x for x in inner if x.get("providerId") == "conditional-level-of-authentication")
                self.call("POST", f"{a}/executions/{cond['id']}/config", {
                    "alias": f"{step[0]}-level", "config": {"loa-condition-level": str(step[3]), "loa-max-age": "0"}})

    def configure(self, redirect_uri, client_jwk):
        self.login_admin()
        loa = json.dumps({"phr": PHR_LEVEL})
        self.call("POST", "/admin/realms", {
            "realm": REALM, "enabled": True, "attributes": {"acr.loa.map": loa},
            "webAuthnPolicyPasswordlessRpId": "localhost",
            "webAuthnPolicyPasswordlessSignatureAlgorithms": ["ES256"],
            "webAuthnPolicyPasswordlessAttestationConveyancePreference": "none",
            "webAuthnPolicyPasswordlessUserVerificationRequirement": "required",
            "webAuthnPolicyPasswordlessRequireResidentKey": "Yes",
        })
        self.passkey_flow = self.flow("passkey", [
            ("auth-username-form", "REQUIRED"),
            ("passkey-level-2", "CONDITIONAL", [
                ("conditional-level-of-authentication", "REQUIRED"),
                ("webauthn-authenticator-passwordless", "REQUIRED"),
            ], PHR_LEVEL),
        ])
        self.password_flow = self.flow("password-only", [("auth-username-password-form", "REQUIRED")])
        _, loc = self.call("POST", f"/admin/realms/{REALM}/clients", {
            "clientId": CLIENT, "protocol": "openid-connect", "publicClient": False,
            "clientAuthenticatorType": "client-jwt", "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
            "redirectUris": [redirect_uri], "webOrigins": [],
            "attributes": {
                "use.jwks.string": "true", "jwks.string": json.dumps({"keys": [client_jwk]}),
                "token.endpoint.auth.signing.alg": "ES256", "pkce.code.challenge.method": "S256",
                "id.token.signed.response.alg": "ES256", "acr.loa.map": loa,
            },
            "authenticationFlowBindingOverrides": {"browser": self.password_flow},
        })
        self.client_id = loc.rsplit("/", 1)[1]
        _, loc = self.call("POST", f"/admin/realms/{REALM}/users", {
            "username": USER, "enabled": True, "email": "alice@example.invalid", "emailVerified": True,
            "firstName": "Alice", "lastName": "Example",
            "credentials": [{"type": "password", "value": USER_PASSWORD, "temporary": False}],
            "requiredActions": ["webauthn-register-passwordless"],
        })
        self.user_id = loc.rsplit("/", 1)[1]

    def bind(self, flow_id):
        c, _ = self.call("GET", f"/admin/realms/{REALM}/clients/{self.client_id}")
        c["authenticationFlowBindingOverrides"] = {"browser": flow_id}
        self.call("PUT", f"/admin/realms/{REALM}/clients/{self.client_id}", c)


# ---------------------------------------------------------- the authenticator

def cbor(v):
    """The CBOR subset WebAuthn needs: ints, bytes, text, maps."""
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for size, code in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | code]) + n.to_bytes(size, "big")
        raise ValueError(n)
    if isinstance(v, bool):
        raise TypeError("bool")
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(type(v))


def js_arg(page, name):
    m = re.search(rf'\b{name}\s*:\s*"([^"]*)"', page)
    if not m:
        raise Failed(f"no {name} in the WebAuthn page")
    return m.group(1)


class Authenticator:
    """A software passkey: one P-256 credential, user presence and user
    verification asserted, "none" attestation, as a platform authenticator
    would report them."""

    UP, UV, AT = 0x01, 0x04, 0x40

    def __init__(self, origin):
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(32)
        self.user_handle = None
        self.count = 0

    def _client_data(self, kind, challenge):
        return json.dumps({"type": kind, "challenge": challenge, "origin": self.origin,
                           "crossOrigin": False}, separators=(",", ":")).encode()

    def register(self, page):
        rp_id = js_arg(page, "rpId")
        self.user_handle = unb64u(js_arg(page, "userid"))
        nums = self.key.public_key().public_numbers()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([self.UP | self.UV | self.AT])
                     + struct.pack(">I", self.count) + b"\0" * 16
                     + struct.pack(">H", len(self.cred_id)) + self.cred_id + cose)
        att = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "clientDataJSON": b64u(self._client_data("webauthn.create", js_arg(page, "challenge"))),
            "attestationObject": b64u(att), "publicKeyCredentialId": b64u(self.cred_id),
            "authenticatorLabel": "corten-e2e", "transports": "internal",
            "authenticatorAttachment": "platform", "error": "",
        }

    def assert_(self, page):
        rp_id = js_arg(page, "rpId")
        self.count += 1
        client_data = self._client_data("webauthn.get", js_arg(page, "challenge"))
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([self.UP | self.UV])
                     + struct.pack(">I", self.count))
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data),
            "signature": b64u(sig), "credentialId": b64u(self.cred_id),
            "userHandle": b64u(self.user_handle), "error": "",
        }


# ------------------------------------------------------------------ the checks

def keycloak_page(browser, gw):
    """Starts a sign-in at the gateway and returns (url, response) at Keycloak's first page."""
    r = browser.request("GET", f"{gw.origin}/.corten/login")
    if r.status != 303:
        raise Failed(f"/.corten/login answered {r.status}")
    return browser.follow(r.header("Location"), gw.origin)


def submit(browser, url, page, form_id, fields):
    forms = forms_of(page.text())
    form = next((f for f in forms if f["id"] == form_id), None)
    if form is None:
        raise Failed(f"no form {form_id!r} at {url}; forms: {[f['id'] for f in forms]}")
    data = dict(form["fields"])
    data.update(fields)
    return browser.request("POST", urllib.parse.urljoin(url, form["action"]), form=data)


def to_gateway(browser, url, r, gw):
    """Follows Keycloak's redirects until it hands the browser back to the gateway's callback."""
    while r.status in (301, 302, 303, 307):
        url = urllib.parse.urljoin(url, r.header("Location"))
        if url.startswith(gw.origin):
            return browser.request("GET", url)
        r = browser.request("GET", url)
    raise Failed(f"Keycloak answered {r.status} at {url} instead of returning to the gateway")


def keycloak_redirect(browser, url, r, gw):
    """Follows redirects within Keycloak; returns (url, page) at the next page."""
    if r.status in (301, 302, 303, 307):
        return browser.follow(urllib.parse.urljoin(url, r.header("Location")), gw.origin)
    return url, r


def run_checks(kc, gw, browser, work, mint_id, mint_pk, stage):
    passkey = Authenticator(kc.base)

    # 1. Control: password only. Keycloak first has the user register a
    #    passkey (their required action), then issues a token whose acr is "1".
    url, page = keycloak_page(browser, gw)
    r = submit(browser, url, page, "kc-form-login", {"username": USER, "password": USER_PASSWORD})
    url, page = keycloak_redirect(browser, url, r, gw)
    check(forms_of(page.text()) and any(f["id"] == "register" for f in forms_of(page.text())),
          "control: after the password, Keycloak asks to register a passkey")
    r = submit(browser, url, page, "register", passkey.register(page.text()))
    done = to_gateway(browser, url, r, gw)
    check(done.status == 403, f"control: a password-only sign-in is refused by the gateway (status {done.status})")
    check(not done.headers_named("Set-Cookie"), "control: no session cookie was set")
    check("not phishing-resistant" in gw.logs(), "control: the gateway logged why")
    if stage == "control":
        return

    # 2. A passkey sign-in, from a browser with no Keycloak session.
    kc.bind(kc.passkey_flow)
    browser = Browser(browser.ctx_ca, browser.origins)
    url, page = keycloak_page(browser, gw)
    r = submit(browser, url, page, "kc-form-login", {"username": USER})
    url, page = keycloak_redirect(browser, url, r, gw)
    check(any(f["id"] == "webauth" for f in forms_of(page.text())), "passkey: Keycloak asks for the passkey")
    r = submit(browser, url, page, "webauth", passkey.assert_(page.text()))
    done = to_gateway(browser, url, r, gw)
    check(done.status == 303 and done.header("Location") == "/",
          f"passkey: the gateway accepts the sign-in (status {done.status})")
    cookie = next((c.split(";", 1)[0] for c in done.headers_named("Set-Cookie")
                   if c.startswith("__Host-corten-session=")), None)
    check(cookie is not None, "passkey: the gateway set its session cookie")

    got = browser.request("GET", f"{gw.origin}/hello")
    check(got.status == 200, f"passkey: a request reaches the program (status {got.status})")
    if getattr(gw, "deployed", False):
        check(got.text() == f"hello, {kc.user_id} (method GET, path /hello, token seen: false)\n",
              "deployed: the Corten program answers as the Keycloak user, and never saw the token")
        prog = gw.program_logs()
        check(f'listen.request method="GET" status="200" principal="{kc.user_id}"' in prog,
              "deployed: the program logged the authenticated request")
        check('authn.ok' in prog and "corten-token-1" not in prog,
              "deployed: the program logged the authentication, not the token")
        direct = gw.direct_request()
        check(direct.startswith("HTTP/1.1 401"),
              "deployed: a request to the program's socket that skips the gateway gets 401")
    else:
        check_echo(got, kc, mint_id, mint_pk)

    # 3. Logout, then the old cookie is refused.
    out = browser.request("POST", f"{gw.origin}/.corten/logout", headers={"Sec-Fetch-Site": "same-origin"})
    check(out.status == 303, f"logout succeeds (status {out.status})")
    replay = browser.request("GET", f"{gw.origin}/hello", headers={"Cookie": cookie})
    check(replay.status == 303 and replay.header("Location") == "/.corten/login",
          "the ended session's cookie is sent back to sign-in")


def check_echo(got, kc, mint_id, mint_pk):
    """The mock program echoed what the gateway sent it."""
    echo = json.loads(got.body)
    check(echo["cookie"] is None, "passkey: the session cookie is not forwarded to the program")
    auth = echo["authorization"] or ""
    check(auth.startswith("Bearer corten-token-1."), "passkey: the program receives a Corten token")
    fields, _, sig = auth[len("Bearer "):].rpartition(".")
    _, key_id, audience, subject, not_after = fields.split(".")
    ed25519.Ed25519PublicKey.from_public_bytes(mint_pk).verify(bytes.fromhex(sig), fields.encode())
    log("ok: the token's Ed25519 signature verifies against the key `corten-gateway check` reported")
    check((key_id, audience, subject) == (mint_id, "api", kc.user_id),
          "the token names the minting key, the grant and the Keycloak user")
    check(0 < int(not_after) - time.time() <= 300 + 5, "the token expires within its 300 s lifetime")


# ------------------------------------------------------------------ program

class Program(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """The mock program: echoes the Authorization and Cookie it was sent."""
    daemon_threads = True


class Echo(http.server.BaseHTTPRequestHandler):
    def address_string(self):
        return "unix"

    def do_GET(self):
        body = json.dumps({"authorization": self.headers.get("Authorization"),
                           "cookie": self.headers.get("Cookie")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


# ------------------------------------------------------------------ gateway

class Gateway:
    def __init__(self, work, ca, issuer):
        self.work, self.ca, self.issuer = work, ca, issuer
        self.port = free_port()
        self.origin = f"https://localhost:{self.port}"
        self.proc = None
        root = os.getcwd()
        self.bin = os.path.join(root, "target", "debug", "corten-gateway")
        self.manifest_bin = os.path.join(root, "target", "debug", "corten-manifest")

    def keys(self):
        w = self.work
        subprocess.run([self.manifest_bin, "keygen", "--id", "gw-mint", "--out", f"{w}/mint.key"],
                       check=True, stdout=subprocess.DEVNULL)
        out = subprocess.run([self.bin, "keygen-client", "--out", f"{w}/client.key"],
                             check=True, capture_output=True, text=True).stdout
        return json.loads(out)

    def write_config(self):
        w = self.work
        conf = f"""origin {self.origin}
listen 127.0.0.1:{self.port}
tls-cert {w}/tls.crt
tls-key {w}/tls.key
issuer {self.issuer}
client-id {CLIENT}
client-key {w}/client.key
mint-key {w}/mint.key
authn-name api
upstream {w}/program.sock
algorithms ES256
"""
        with open(f"{w}/gateway.conf", "w") as f:
            f.write(conf)
        out = subprocess.run([self.bin, "check", "--config", f"{w}/gateway.conf"],
                             capture_output=True, text=True, check=False)
        if out.returncode != 0:
            raise Failed(f"corten-gateway check: {out.stderr.strip()}")
        line = next(l for l in out.stdout.splitlines() if l.startswith("program manifest line: "))
        key_id, _, hexkey = line.rsplit(" ", 1)[1].partition(":")
        return key_id, bytes.fromhex(hexkey)

    def start(self, browser):
        env = dict(os.environ, SSL_CERT_FILE=self.ca)
        # Open for the life of the child process that writes to it; closed in stop().
        self.log = open(f"{self.work}/gateway.log", "w")  # noqa: SIM115
        self.proc = subprocess.Popen([self.bin, "serve", "--config", f"{self.work}/gateway.conf"],
                                     stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log, env=env)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise Failed(f"corten-gateway exited {self.proc.returncode}; see {self.work}/gateway.log")
            try:
                if browser.request("GET", f"{self.origin}/.corten/login").status == 303:
                    return
            except OSError:
                pass
            time.sleep(0.5)
        raise Failed(f"corten-gateway did not load the provider within 60 s; see {self.work}/gateway.log")

    def logs(self):
        with open(f"{self.work}/gateway.log") as f:
            return f.read()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.proc:
            self.log.close()


# ---------------------------------------------------------------- deployment

def podman(*args, capture=False):
    """Runs podman; raises Failed with its stderr when it fails."""
    r = subprocess.run(["podman", *args], capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise Failed(f"podman {args[0]} {args[1] if len(args) > 1 else ''}: {r.stderr.strip()[-2000:]}")
    return r.stdout if capture else None


class Deployment:
    """Keycloak, the gateway and a sandboxed Corten program in one pod. The
    repository's binaries are built for Linux in the pinned rust image; the
    work directory is mounted at /work; the program's socket lives on a pod
    volume shared with the gateway, never on the macOS bind mount."""

    deployed = True

    def __init__(self, work, ca, build_cache):
        tag = os.getpid()
        self.work, self.ca = work, ca
        self.pod = f"corten-e2e-{tag}"
        self.sock_volume = f"corten-e2e-sock-{tag}"
        self.cache = build_cache or f"corten-e2e-build-{tag}"
        self.keep_cache = build_cache is not None
        self.kc_port, self.port = free_port(), free_port()
        self.origin = f"https://localhost:{self.port}"
        self.issuer = f"https://localhost:{self.kc_port}/realms/{REALM}"
        self.gw_name, self.prog_name = f"{self.pod}-gw", f"{self.pod}-prog"
        self.created = []  # ("pod"|"volume", name), removed in stop()

    def run(self, *cmd, capture=True):
        """Runs a command in a throwaway container with /work mounted."""
        return podman("run", "--rm", "-v", f"{self.work}:/work:z", "-e", "HOME=/root",
                      RUST_IMAGE, *cmd, capture=capture)

    def build(self):
        for suffix in ("target", "cargo"):
            name = f"{self.cache}-{suffix}"
            exists = subprocess.run(["podman", "volume", "exists", name], check=False).returncode == 0
            if not exists:
                podman("volume", "create", name)
                if not self.keep_cache:
                    self.created.append(("volume", name))
        log("building the Linux binaries in the pinned rust image (minutes when the cache is cold)")
        podman("run", "--rm", "--memory", "12g", "-e", "CARGO_BUILD_JOBS=4",
               "-v", f"{os.getcwd()}:/src:ro", "-w", "/src",
               "-v", f"{self.cache}-target:/tmp/target", "-v", f"{self.cache}-cargo:/usr/local/cargo/registry",
               "-v", f"{self.work}:/work:z", "-e", "CARGO_TARGET_DIR=/tmp/target", RUST_IMAGE, "bash", "-c",
               "set -e; cargo build -q --locked -p corten-gateway -p corten-manifest -p corten-sandbox;"
               " cargo build -q --locked -p corten-std --example hello_listener;"
               " mkdir -p /work/bin; cp /tmp/target/debug/corten-gateway /tmp/target/debug/corten-manifest"
               " /tmp/target/debug/corten-sandbox /tmp/target/debug/examples/hello_listener /work/bin/")

    def keys(self):
        self.run("/work/bin/corten-manifest", "keygen", "--id", "gw-mint", "--out", "/work/mint.key")
        jwk = json.loads(self.run("/work/bin/corten-gateway", "keygen-client", "--out", "/work/client.key"))
        self.trusted = self.run("/work/bin/corten-manifest", "keygen", "--id", "deploy",
                                "--out", "/work/deploy.key").strip()
        return jwk

    def write_config(self):
        conf = f"""origin {self.origin}
listen 0.0.0.0:{self.port}
tls-cert /work/tls.crt
tls-key /work/tls.key
issuer {self.issuer}
client-id {CLIENT}
client-key /work/client.key
mint-key /work/mint.key
authn-name api
upstream /run/app/app.sock
algorithms ES256
"""
        with open(f"{self.work}/gateway.conf", "w") as f:
            f.write(conf)
        out = self.run("/work/bin/corten-gateway", "check", "--config", "/work/gateway.conf")
        line = next(ln for ln in out.splitlines() if ln.startswith("program manifest line: "))
        entry = line.rsplit(" ", 1)[1]
        # The program's grants: trust the gateway's minting key, and listen
        # on the shared volume with that authenticator.
        os.makedirs(f"{self.work}/prog", mode=0o755)
        with open(f"{self.work}/grants", "w") as f:
            f.write(f"authn api token {entry}\nlisten app unix /run/app/app.sock authn api\n")
        self.run("/work/bin/corten-manifest", "sign", "--key", "/work/deploy.key", "--grants", "/work/grants",
                 "--program", "/work/bin/hello_listener", "--valid-for", "1",
                 "--out", "/work/prog/manifest", "--signature", "/work/prog/manifest.sig")
        key_id, _, hexkey = entry.partition(":")
        return key_id, bytes.fromhex(hexkey)

    def create_pod(self):
        podman("pod", "create", "--name", self.pod,
               "-p", f"127.0.0.1:{self.kc_port}:{self.kc_port}", "-p", f"127.0.0.1:{self.port}:{self.port}")
        self.created.append(("pod", self.pod))
        podman("volume", "create", self.sock_volume)
        self.created.append(("volume", self.sock_volume))

    def start(self, browser):
        common = ["run", "-d", "--pod", self.pod, "-v", f"{self.work}:/work:z",
                  "-v", f"{self.sock_volume}:/run/app"]
        # The program, under the launcher: Landlock from its signed manifest;
        # it may read only its own manifest directory, not the keys in /work.
        podman(*common, "--name", self.prog_name, RUST_IMAGE,
               "/work/bin/corten-sandbox", "--manifest", "/work/prog/manifest",
               "--signature", "/work/prog/manifest.sig", "--trusted-key", self.trusted,
               "--serial-state", "/work/serial", "--system", "--ro", "/work/prog",
               "--exec", "/work/bin/hello_listener", "--",
               "/work/bin/hello_listener", "/work/prog/manifest", "/work/prog/manifest.sig", self.trusted)
        deadline = time.monotonic() + 30
        while "hello_listener: serving" not in self.program_logs():
            if time.monotonic() > deadline:
                raise Failed("the program did not start; its log:\n" + self.program_logs()[-2000:])
            time.sleep(0.5)
        podman(*common, "--name", self.gw_name, "-e", "SSL_CERT_FILE=/work/ca.crt", RUST_IMAGE,
               "/work/bin/corten-gateway", "serve", "--config", "/work/gateway.conf")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                if browser.request("GET", f"{self.origin}/.corten/login").status == 303:
                    return
            except OSError:
                pass
            time.sleep(0.5)
        raise Failed("the gateway did not load the provider within 60 s; its log:\n" + self.logs()[-2000:])

    def _logs(self, name):
        r = subprocess.run(["podman", "logs", name], capture_output=True, text=True, check=False)
        return r.stdout + r.stderr

    def logs(self):
        return self._logs(self.gw_name)

    def program_logs(self):
        return self._logs(self.prog_name)

    def direct_request(self):
        """One request straight to the program's socket, from inside the pod."""
        return podman("exec", self.gw_name, "perl", "-MIO::Socket::UNIX", "-e",
                      '$s = IO::Socket::UNIX->new(Peer => "/run/app/app.sock") or die "connect: $!";'
                      ' print $s "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";'
                      ' print while <$s>;', capture=True)

    def stop(self):
        for kind, name in reversed(self.created):
            if kind == "pod":
                subprocess.run(["podman", "pod", "rm", "-f", "-t", "5", name],
                               capture_output=True, check=False)
            else:
                subprocess.run(["podman", "volume", "rm", "-f", name], capture_output=True, check=False)
        left = [n for k, n in self.created
                if subprocess.run(["podman", k, "exists", n], check=False).returncode == 0]
        if left:
            log(f"could not remove: {left}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--keep-dir", action="store_true", help="keep the work directory (certificates, logs) after the run")
    ap.add_argument("--stage", default="all", help=argparse.SUPPRESS)
    ap.add_argument("--deployed", action="store_true",
                    help="run the gateway and a sandboxed Corten program in a podman pod")
    ap.add_argument("--build-cache", metavar="NAME",
                    help="with --deployed: keep the Linux build in volumes NAME-target and NAME-cargo")
    args = ap.parse_args()
    if args.build_cache and not args.deployed:
        ap.error("--build-cache goes with --deployed")
    if args.build_cache and not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,40}", args.build_cache):
        ap.error("--build-cache: lowercase letters, digits, '.', '_' and '-'")
    # Under the repository, not the system temporary directory: podman on macOS
    # runs in a VM that shares the user's directories but not /var/folders.
    base = os.path.abspath(".work")
    os.makedirs(base, exist_ok=True)
    work = tempfile.mkdtemp(prefix="gateway-keycloak-e2e-", dir=base)
    os.chmod(work, 0o755)  # the container reads the certificates
    log(f"work directory {work}")
    ca = make_pki(work)
    os.chmod(os.path.join(work, "tls.key"), 0o644)  # Keycloak runs as a different uid in the container
    if args.deployed:
        return deployed(work, ca, args)
    kc = Keycloak(work, ca)
    gw = Gateway(work, ca, f"{kc.base}/realms/{REALM}")
    program = None
    try:
        subprocess.run(["cargo", "build", "-q", "-p", "corten-gateway", "-p", "corten-manifest"], check=True)
        jwk = gw.keys()
        mint_id, mint_pk = gw.write_config()
        kc.start()
        log(f"Keycloak up at {kc.base}")
        kc.configure(f"{gw.origin}/.corten/callback", jwk)
        program = Program(f"{work}/program.sock", Echo)
        threading.Thread(target=program.serve_forever, daemon=True).start()
        browser = Browser(ca, [gw.origin, kc.base])
        gw.start(browser)
        log(f"gateway up at {gw.origin}")
        run_checks(kc, gw, browser, work, mint_id, mint_pk, args.stage)
        log("all checks passed")
        return 0
    except Failed as e:
        log(f"FAILED: {e}")
        return 1
    except KeyboardInterrupt:
        log("interrupted; cleaning up")
        return 130
    finally:
        gw.stop()
        if program is not None:
            program.shutdown()
            program.server_close()
        kc.stop()
        if not args.keep_dir:
            shutil.rmtree(work, ignore_errors=True)


def deployed(work, ca, args):
    """The --deployed run: the same checks against the pod."""
    d = Deployment(work, ca, args.build_cache)
    kc = Keycloak(work, ca, port=d.kc_port, pod=d.pod)
    try:
        d.build()
        jwk = d.keys()
        mint_id, mint_pk = d.write_config()
        d.create_pod()
        kc.start()
        log(f"Keycloak up at {kc.base} (in pod {d.pod})")
        kc.configure(f"{d.origin}/.corten/callback", jwk)
        browser = Browser(ca, [d.origin, kc.base])
        d.start(browser)
        log(f"gateway up at {d.origin}; program under corten-sandbox")
        run_checks(kc, d, browser, work, mint_id, mint_pk, args.stage)
        log("all checks passed")
        return 0
    except Failed as e:
        log(f"FAILED: {e}")
        return 1
    except KeyboardInterrupt:
        log("interrupted; cleaning up")
        return 130
    finally:
        kc.stop()
        d.stop()
        if not args.keep_dir:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
