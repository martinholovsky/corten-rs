# Exchange gateway: phishing-resistant sign-in for Corten programs (design note, 2026-11-14)

Status: **Q1 to Q4 decided (owner, 2026-11-14, the recommendation on all four):** (1) a separate `corten-gateway` as an identity-aware reverse proxy; (2) `openidconnect`, after the Phase 5 review; (3) `acr` `phr` by default, with a per-grant option to require `phrh`, and the signing key in a 0600 file, rotated through the manifest; (4) Kanidm as the reference provider, Keycloak if Kanidm does not return `acr` `phr`. Phase 6, batch 4, the item after step 1 (`phase-6.md`, remaining work). It implements spec section 8, question 23: Corten accepts only phishing-resistant authentication, users sign in with passkeys at an identity provider Corten does not build, and programs accept only a Corten token (`corten_std::authz::TokenAuthenticator`). Nothing here is built.

## What it is for

A Corten program obtains an `Authenticated` principal only from a token signed by a key its manifest names. Something has to sign those tokens, and only after a person has signed in with a phishing-resistant method. The gateway does that, and nothing else:

- It is the OpenID Connect relying party for the identity provider (Authorization Code with PKCE, the only sanctioned interactive flow).
- It accepts a sign-in only when the provider asserts a phishing-resistant method.
- It issues short-lived Corten tokens that only Corten programs accept. It never forwards the provider's token inward, which is the "internal identity token" pattern (sota-code-security rules/03 §6).

The prelude stays as step 1 left it: no JWT or OIDC code in any program. The provider's format, discovery and key fetching live only in the gateway.

## Facts this design rests on (checked 2026-11-14)

- **How a provider says "phishing-resistant".** OpenID Connect EAP ACR Values 1.0 (Final, 15 June 2025) defines the `acr` values `phr`: no party under the relying party's control can learn enough to sign in as the user. It also defines `phrh`: the same, with the authentication secret held in a hardware-protected device. The spec says FIDO authenticators satisfy them, and that a relying party should check the returned `acr` is one it requested.
- **What `amr` does not say.** RFC 8176's `amr` values describe methods (for example `hwk`, proof of possession of a hardware-secured key). None is defined as phishing-resistant, so the gateway must not infer phishing resistance from `amr`.
- **Libraries** (crates.io, 2026-11-14):
  - `openidconnect` 4.1.0 (MIT, released 2026-10-31) implements the relying-party flow: discovery, PKCE, `nonce`, and ID-token validation.
  - `jsonwebtoken` 12.0.0 (MIT) was released 2026-11-13, one day before this note. That is too recent to adopt without a waiting period.
  - `jwt-simple` 0.15.0 is ISC.
  - None has had the Phase 5 review yet (design principle 6).
- **Not verified here:** which providers return `acr` = `phr` or `phrh` for a passkey sign-in, and how each is configured to. It is measured per provider in the prototype (Q4).

## Threat model, briefly

The gateway is part of the trusted base and close to tier 0. Whoever holds its signing key can mint any principal for every program that trusts it.

| Threat | Mitigation |
| --- | --- |
| A sign-in that was not phishing-resistant (password, SMS, a downgraded flow) | Request `acr_values`, then refuse unless the ID token's `acr` is in the configured set. Nothing weaker can be configured: the set is a subset of `phr`, `phrh` |
| A forged or replayed provider response | `openidconnect`'s validation: signature against the provider's keys, `iss`, `aud` (the gateway's client ID), `exp`, and `nonce` bound to the sign-in; PKCE (S256) and `state` checked before the code is exchanged |
| Theft of the gateway's signing key | A key file at mode 0600 (as `corten-manifest keygen` writes it), the gateway run under `corten-sandbox`, outbound network only to the provider, two keys in each program's manifest for rotation. A hardware key is a later option (Q3) |
| A stolen Corten token | Lifetime at most 900 s in the prelude, minted shorter (300 s by default). Tokens never reach a browser: the gateway sends them to the program alongside each request |
| Abuse of the sign-in endpoint | Rate limits per client address and per session at the gateway, the only component that sees addresses |
| Stale access after a user is removed | Tokens expire within minutes, and sessions are re-checked with the provider at their absolute timeout. Back-channel logout and CAEP are later options |

## Questions for the owner

**Q1. What shape is the gateway?**
- **A. A separate Corten binary, `corten-gateway`, as an identity-aware reverse proxy (recommended).**
  - It runs the browser sign-in and holds the session (a server-side session with idle and absolute timeouts).
  - For each request it mints a Corten token and forwards it with the request to the program over a local socket.
  - **Pros:** the browser never holds a token, and programs need nothing beyond step 1.
  - **Cons:** a new long-running component, and it needs Corten programs that accept HTTP (batch 6's listener) to be useful end to end.
- B. A token-exchange service (RFC 8693). Clients obtain provider tokens themselves and exchange them for Corten tokens.
  - **Pros:** no proxy.
  - **Cons:** every client handles two token types, and the provider's token reaches the client.
- C. A library inside each program. Rejected: it puts OIDC and JWT code in every program's trusted base, the reason question 23 chose a gateway.

**Q2. Which library implements the OIDC relying party?**
- **A. `openidconnect` (recommended).** It performs the protocol steps (PKCE, `nonce`, ID-token checks), so the gateway does not hand-assemble them, and its crypto backend can be chosen to match the prelude's (the provider choice of question 13). Cost: its dependency set goes through the Phase 5 review first, and the count is measured then.
- B. A JWT library (`jsonwebtoken` or `jwt-simple`) with the flow written in the gateway. Fewer dependencies, but hand-written protocol steps, which the secure-coding rules count as a finding until proven otherwise.

**Q3. Which methods count, and where is the signing key?**
- **Default `acr`: `phr`, which synced passkeys satisfy, with a per-grant option to require `phrh` (hardware-protected), logged at each sign-in (recommended).** Requiring `phrh` everywhere would refuse synced passkeys, which most consumer devices use.
- **Key: a file at mode 0600 on the gateway host, rotated through the manifest's key list (recommended).** A TPM or HSM is a later option, decided when a deployment needs it.

**Q4. Which provider is the reference for the prototype?**
- **A. Kanidm (recommended to try first):** written in Rust, self-hosted, passkeys and OIDC. Whether it returns `acr` = `phr`/`phrh` is not verified; if it does not, Q4 falls to B.
- B. Keycloak: widely deployed; it maps authentication flows to `acr` levels.
- Either way the gateway is provider-neutral; the reference is the one the tests run against.

## Phase 5 review of `openidconnect` 4.1.0 (2026-11-14): fails the policy as is

Two scratch crates were checked with the repository's `deny.toml` (cargo-deny 0.20.2, rustc 1.99.1):

| Set | Packages | Advisories | Duplicate versions | Licences |
| --- | ---: | --- | --- | --- |
| (a) `default-features = false` (the gateway brings its own HTTP client) | 195 | **RUSTSEC-2023-0071** (`rsa` 0.9.10, Marvin attack) | **14 crates** twice | pass |
| (b) default (`reqwest`, `rustls`) | 252 | the same | 15 | **refused**: `webpki-roots` is CDLA-Permissive-2.0 (question 13) |

The "unlicensed" error for the scratch crate itself is the fixture's missing licence field, not a finding.

- **Duplicates.** `openidconnect` mixes current RustCrypto crates (`ed25519-dalek` 3, `p256` 0.14) with older ones (`rsa` 0.9, which needs `sha2` 0.10, `hmac` 0.12, `digest` 0.10 and others). `multiple-versions = "deny"` refuses this before the gateway even joins the workspace.
- **The advisory** leaks an RSA **private** key through timing. The gateway would only verify RS256 signatures with a provider's public key, so it would not be exposed. Still, the policy fails, and the fix (`rsa` 0.10) is outside what 4.1.0 accepts (`rsa = "0.9.2"`).
- **Upstream** (`ramosbugs/openidconnect-rs`, read 2026-11-14): `main` still pins `rsa` 0.9.2, `hmac` 0.12 and `sha2` 0.10. Open pull requests #244 ("bump crypto dependencies to newly released versions") and #214 (an RSA update for RUSTSEC-2023-0071) would resolve both findings. Neither is merged.

Q2's premise (adopt after a passing review) did not hold, so Q2 went back to the owner.

**Q2 decided again (owner, 2026-11-14): option C**, against the recommendation (A: wait for upstream #244 and #214). The gateway implements the relying-party steps itself on a small set. The owner gave no reason; it is to be recorded here when given. Rejected: A, waiting on an upstream schedule; B, `deny.toml` exceptions that would also loosen the prelude's policy.

**Phase 5 review of the chosen set (2026-11-14).** The `corten-gateway` crate in the workspace, against the shared lockfile and `deny.toml`:
- **Reused from the trusted base, no new code:** signatures (RS256, ES256, Ed25519) and SHA-256 through `aws-lc-rs` 1.19.0; TLS through `rustls` 0.23.46 and `tokio-rustls` 0.26.6; `tokio`, `http`, `base64`, `serde`, `ed25519-compact`.
- **New:** 10 packages, the lockfile going from 240 to 251.
  - `hyper` 1.12.0 (HTTP/1 only, server and client), `hyper-util` 0.1.21, `http-body` 1.1.0, `http-body-util` 0.1.5, `httparse` 1.10.1, `httpdate` 1.0.3, `want` 0.3.2, `try-lock` 0.2.5;
  - `serde_json` 1.0.154 and `zmij` 1.0.23, its float formatter.
  - All MIT or MIT/Apache-2.0, released between 2023-08 and 2026-10, with no C or assembly sources. `httparse`, `serde_json` and `zmij` have build scripts.
- **`cargo deny check advisories bans licenses sources`:** all four pass, with no new `skip` or exception.
- **The cost of C:** the protocol steps are hand-written (Authorization Code with PKCE, `state`, `nonce`, ID-token validation, discovery, JWKS handling). The secure-coding rules count that as a finding until reviewed. So every step gets a refusal test and a mutation, and the code is listed for the independent review beside the encoders.

## Prototype plan (after the answers)

1. **Phase 5 review of the chosen library** (licences under `deny.toml`, advisories, maintenance, package count), recorded in `phase-6.md`.
2. **`corten-gateway` crate, outside the prelude.** ID-token validation, the authorization-code flow, token minting, the session store, the HTTPS client and the browser-facing rules are **built** (2026-11-15: 38 tests, 100 of 100 mutations caught; `phase-6.md`). The minting key is a `corten-manifest keygen` file, so operators need no new tool. The client assertion follows RFC 10070, which updated RFC 7523 in November 2026: `aud` is the issuer identifier as the sole value, never the token endpoint. The rest covers:
   - the sign-in flow with `acr` enforcement, the session, token minting, and the forwarding proxy;
   - unit tests for each refusal (missing or unrequested `acr`, bad `nonce`, `state`, `aud` or `iss`, expired);
   - a mutation per control, shown to fail a test.
3. **An end-to-end test against the reference provider in a container:**
   - a passkey sign-in (a virtual authenticator) is accepted;
   - a sign-in whose `acr` is not phishing-resistant is refused, as the control.
4. **Integration with a Corten program waits for batch 6's listener.** Until then the program side is step 1's `TokenAuthenticator`, tested with tokens the gateway minted.

## Q5 to Q7: the server and the proxy (owner, 2026-11-15, the recommendation on all three)

- **Q5. TLS for browsers ends at the gateway.** The gateway serves HTTPS itself (rustls, TLS 1.3, certificate and key files from the operator), so it trusts no proxy headers, and rate limits key on the connection's address. Rejected: plain HTTP behind an operator proxy, which would make the gateway trust `X-Forwarded-*` from one configured address. ACME is a later add-on.
- **Q6. Forwarding to the program:** over a **Unix domain socket** named in configuration, with **`Authorization: Bearer <Corten token>`**. The client's `Authorization` is replaced, and the gateway's session cookie, hop-by-hop and forwarding headers are removed. File permissions decide who can connect, so nothing on the network can bypass the gateway, and the sandbox can grant the socket path. This is the contract batch 6's listener implements. Rejected: loopback TCP, which any local process could reach directly.
- **Q7. Order:** build and test the server and proxy now against a plain test upstream; batch 6's listener implements the program side later. Rejected: designing the listener first.

## Failure modes of sign-in (sota-architecture rules/04 section 12)

The identity provider is a T0 dependency: sign-in fails without it, and the gateway fails closed. Programs keep serving sessions that already exist.

| Dependency | Slow | Down | Garbage |
| --- | --- | --- | --- |
| Discovery and key set (GET) | 5 s connect, 10 s request; at most 3 attempts, full-jitter backoff | at start: keep retrying, answer sign-in with 503 meanwhile; later: keep the last good key set | metadata refused (`flow::discover`); key set refused (`Jwks::parse`); sign-in refused |
| Key set, unknown `kid` | as above | the token is refused | re-fetched at most once a minute (`RefreshLimiter`) |
| Token endpoint (POST) | 10 s, **no retry** (the code is single-use) | circuit breaker opens after 5 failures for 30 s, logged; sign-in refused meanwhile | ID token refused by `idtoken::validate` |

These defaults are configured values, not measured from a provider. Tune them to the reference provider's p99 in the end-to-end test.

## What it cannot claim

The gateway can enforce that the provider *asserted* a phishing-resistant method. It cannot check that the assertion is true: that rests on the provider's configuration, which `tcb.md` will list as a trusted-base assumption. No ledger row moves because of the gateway; the authentication rows move with strategy 2's corpus cases (question 14).
