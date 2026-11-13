# Exchange gateway: phishing-resistant sign-in for Corten programs (design note, 2026-11-14)

Status: **proposed; owner decisions needed on Q1 to Q4** (below). Phase 6, batch 4, the item after step 1 (`phase-6.md`, remaining work). It implements spec section 8, question 23: Corten accepts only phishing-resistant authentication, users sign in with passkeys at an identity provider Corten does not build, and programs accept only a Corten token (`corten_std::authz::TokenAuthenticator`). Nothing here is built.

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

## Prototype plan (after the answers)

1. **Phase 5 review of the chosen library** (licences under `deny.toml`, advisories, maintenance, package count), recorded in `phase-6.md`.
2. **`corten-gateway` crate, outside the prelude.** It covers:
   - the sign-in flow with `acr` enforcement, the session, token minting, and the forwarding proxy;
   - unit tests for each refusal (missing or unrequested `acr`, bad `nonce`, `state`, `aud` or `iss`, expired);
   - a mutation per control, shown to fail a test.
3. **An end-to-end test against the reference provider in a container:**
   - a passkey sign-in (a virtual authenticator) is accepted;
   - a sign-in whose `acr` is not phishing-resistant is refused, as the control.
4. **Integration with a Corten program waits for batch 6's listener.** Until then the program side is step 1's `TokenAuthenticator`, tested with tokens the gateway minted.

## What it cannot claim

The gateway can enforce that the provider *asserted* a phishing-resistant method. It cannot check that the assertion is true: that rests on the provider's configuration, which `tcb.md` will list as a trusted-base assumption. No ledger row moves because of the gateway; the authentication rows move with strategy 2's corpus cases (question 14).
