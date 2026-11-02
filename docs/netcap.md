# NetCap, name resolution and the TLS client (design, not built)

Status: design, 2026-11-02 (Phase 6, batch 5, strategy 7). **Built so far (`corten_std::net`):** the `net` grant, the address check (section 4, step 1), the connect pass with timeouts (step 2), the TLS 1.3 client with operator CRLs or a logged `Unchecked` (step 3), the security-state log record at every connection, and the sandbox's port rule. **Also built:** name resolution with `hickory-resolver` (Linux) and section 3: the `net.dns` record and warning on every change of DNS state, the DNSSEC probe, the public-resolver probe (test name only), and the switch to Cloudflare or Google over DNS over TLS only with `dns fallback NAME`. **Not built:** DNSSEC validation inside the prelude (question 17: measured before it is enabled), DNS over HTTPS (the fallback uses DNS over TLS), and Happy Eyeballs (addresses are tried in the resolver's order). Owner decisions already taken for this design:
- grants name exact destinations;
- every resolved address is checked, with private ranges and the metadata address refused unless granted;
- default timeouts under a hard ceiling;
- TLS 1.3 only.

Questions 16 to 19 (spec section 8) were decided on 2026-11-02, the recommendation on all four: probe and log, fallback only by opt-in; `hickory-resolver` with DoT/DoH; operator-supplied CRLs with their expiry enforced; manifest expiry, serial and key identifiers. Every CWE below is quoted from `ledger/cwe-ledger.csv`, with its current bucket, all C today. **The ledger is not changed by this document.** Its `mechanism` column records enforced mechanisms, so each row is updated, and gets a corpus case where an E claim is made, only when its mitigation is built and tested (section 6).

## 1. What NetCap is for

A Corten program that calls another service, such as a payment API, an identity provider or an internal service. Nothing in the program may send traffic anywhere else. Spec 4.3: no network authority is ambient; `main` receives capabilities from the signed manifest.

1. The deployer grants a destination by name: `net NAME HOST:PORT [private]`.
2. The program takes the capability by its manifest name (`Capabilities::take_net`). It never chooses a host.
3. `corten-std` resolves the name, checks every address, connects only to a checked address, and runs TLS 1.3 with the certificate verified against the granted host name. The defaults are a 10 s connect timeout and 30 s for reads and writes; a caller may lower them, never above a 300 s ceiling.

Why names and not addresses: certificates are issued for names, so TLS needs the host name anyway. Cloud and CDN services also change addresses, so a manifest that pins them breaks without warning. A deployment with fixed endpoints may still grant `IP:PORT` with the certificate name (question 17).

## 2. Constraints measured on 2026-11-01 and 2026-11-02

- **No `std::net` in the prelude.** The profile bans `std::net` (`TcpStream`, `connect`, `connect_timeout`, `ToSocketAddrs`; `crates/cargo-corten/src/profile.rs`), and `corten-std` must pass its own profile. Sockets therefore go through `rustix`, which provides `socket`, `connect`, `set_socket_timeout`, `socket_error` and `poll`; resolution needs a dependency (question 17).
- **The system resolver sends plain DNS.** glibc's `getaddrinfo` sends unencrypted, unauthenticated DNS over UDP to the servers in `/etc/resolv.conf`, with a 5 s timeout and 2 attempts by default. It validates no DNSSEC itself: its `trust-ad` option only trusts the AD bit an upstream resolver sets (man resolv.conf).
- **systemd-resolved does not encrypt by default.** It can use DNS over TLS upstream, but `DNSOverTLS=` defaults to "no" and `DNSSEC=` to "allow-downgrade" (man resolved.conf).
- **rustls checks the chain and the host name only, at the handshake.** It checks revocation only when given CRLs (`with_crls`), fetches none, and logs a stapled OCSP response as "Unvalidated". It does not enforce Certificate Transparency. `rustls-native-certs` loads a snapshot of the platform's roots.
- **Neither resolver connects or fails over.** Connection failover and Happy Eyeballs are the caller's job.
  - glibc sorts answers by RFC 3484 rules (`/etc/gai.conf`), which can undo a server's round-robin order.
  - `hickory-resolver` 0.26.3 defaults to AAAA and A queried in parallel, IPv6 first.
  - hickory's `RoundRobin` and `QueryStatistics` options order the name servers it queries, not the answers.
- **Validation is detectable.** A validating resolver answers SERVFAIL for the deliberately broken test domain `dnssec-failed.org`, and NOERROR with checking disabled (`+cd`). Checked with `dig` against 1.1.1.1 and 8.8.8.8; a correctly signed name returns the AD bit.
- **The public resolvers** (from their documentation, checked against the pages on 2026-11-02):

  | | Cloudflare | Google |
  | --- | --- | --- |
  | DNS over HTTPS | `https://cloudflare-dns.com/dns-query` | `https://dns.google/dns-query` |
  | DNS over TLS | port 853, `1.1.1.1` / `1.0.0.1` or `one.one.one.one` | port 853, `dns.google` |
  | DNSSEC validation | "1.1.1.1 is a DNSSEC-validating resolver" | "validate responses for correct authentication" |
  | Query logs | "Cloudflare will delete the Public Resolver Logs within 25 hours"; aggregated data may be kept indefinitely | temporary logs deleted "within 24-48 hours"; sampled permanent logs with no stated retention |

## 3. Name resolution: what Corten does and what it logs

The prelude never resolves silently. When a `NetCap` first resolves, it writes one record through the prelude's log sink (`log_record!`, so names and errors are neutralized, CWE-117), then one record for every later change.

| Field | Values |
| --- | --- |
| `dns.source` | `system` (from `/etc/resolv.conf`) or a fallback named in the manifest (`cloudflare`, `google`) |
| `dns.transport` | `udp-tcp` (plain), `dot` or `doh` |
| `dns.dnssec` | `validating` (the test name failed), `not-validating` (it resolved), or `unknown` (the probe could not run) |
| `dns.fallback` | `none`, `probed-available`, `probed-unavailable` or `switched`, with the reason |

**Warnings.** A plain transport, or a `dnssec` value other than `validating`, is logged at warning level, with the risk named: "DNS answers for this grant are unauthenticated; integrity rests on TLS host-name verification alone". The developer or operator therefore always knows what the program trusts.

**Fallback to a public resolver.** The probe tests whether DoT or DoH to Cloudflare or Google answers, and whether it validates. A switch happens only when the manifest opts in (`dns fallback cloudflare` or `dns fallback google`), and the switch is logged. This is the recommendation recorded as question 16, for three reasons:
- **Internal names.** Split-horizon names exist only in the system's DNS. A silent switch breaks every internal name.
- **A third party sees the queries.** Every query would go to a party outside the deployer's control, along with the deployment's network address (retention above).
- **The capability model.** The resolver itself is network egress, so it must be granted like any other destination.

Without the opt-in, the probe result is still logged, so the operator sees that a validating, encrypted path was available.

Resolving over DoT or DoH and validating DNSSEC need a resolver that implements them; the system resolver cannot (question 17).

## 4. Connecting

1. Resolve once and check every address:
   - canonicalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) first;
   - refuse loopback, private, link-local, unique-local, multicast, unspecified and the metadata addresses (`169.254.169.254`, `fd00:ec2::254`) unless the grant says `private`.

   If **any** address is refused, the whole lookup is refused and logged. A mixed answer is how DNS rebinding looks.
2. Try the checked addresses in the resolver's order. Each attempt gets its share of one connect budget (10 s default, 300 s ceiling). There is one pass, no re-resolution between check and connect, and no retry after a request has been sent: a non-idempotent request is never replayed (spec 4.8: replay and duplicate actions stay C).
3. Run TLS 1.3 only, with the certificate verified against the granted host name. There is no API to disable verification and no plaintext API. Revocation follows question 18, and the mode in force is logged at the first connection.
4. Load balancing stays on the server side. The client does not defeat it: it keeps no cache beyond the record's TTL, and the resolver's order is used as returned.

## 5. Attack vectors, CWEs and mitigations

| # | Attack vector | CWEs (ledger) | Mitigation in this design | Verified by (planned) |
| --- | --- | --- | --- | --- |
| A1 | Spoofed or forged DNS answer | 345 Insufficient Verification of Data Authenticity; 940 Improper Verification of Source of a Communication Channel; 350 Reliance on Reverse DNS Resolution for a Security-Critical Action | TLS host-name verification binds the connection to the granted name. DNSSEC validation where available (question 17). Status logged | A test where a spoofed address with a valid certificate for another name is refused at the handshake |
| A2 | DNS rebinding to an internal address | 367 Time-of-check Time-of-use (TOCTOU) Race Condition; 918 Server-Side Request Forgery (SSRF) | Resolve once, check, connect only to checked addresses; refuse mixed answers | A test resolver returning public then private addresses: refused |
| A3 | Answer pointing at private ranges or cloud metadata | 918; 923 Improper Restriction of Communication Channel to Intended Endpoints; 941 Incorrectly Specified Destination in a Communication Channel | Address check with IPv4-mapped canonicalization; `private` only by grant | A table test over every refused range, including `::ffff:169.254.169.254` |
| A4 | Plain DNS observed or altered on the path | 319 Cleartext Transmission of Sensitive Information; 300 Channel Accessible by Non-Endpoint; 200 Exposure of Sensitive Information to an Unauthorized Actor | DoT or DoH (system support or opt-in fallback); otherwise a warning in the log | A log test for each transport value |
| A5 | DNSSEC downgrade (`allow-downgrade`, non-validating resolver) | 757 Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade') | Validation probe; status logged as a warning | A probe test against a validating and a non-validating stub |
| A6 | Silent fallback sends queries to a third party | 359 Exposure of Private Personal Information to an Unauthorized Actor; 201 Insertion of Sensitive Information Into Sent Data | Fallback only by manifest opt-in; every switch logged | A test that without the opt-in, no query leaves for a public resolver |
| A7 | Security-relevant resolution state not recorded | 778 Insufficient Logging; 223 Omission of Security-relevant Information | The section 3 record at first use and on every change | A log-shape test |
| A8 | Log injection through host names, answers or errors | 117 Improper Output Neutralization for Logs (E, awaiting the encoder review) | Only `log_record!`, never string formatting | The existing encoder tests |
| A9 | Certificate not validated, or validated wrongly | 295 Improper Certificate Validation; 296 Improper Following of a Certificate's Chain of Trust; 297 Improper Validation of Certificate with Host Mismatch; 298 Improper Validation of Certificate Expiration | rustls-webpki at the handshake; no API to disable it | Tests with a wrong host, an expired certificate, an unknown root and a broken chain |
| A10 | Revoked certificate accepted | 299 Improper Check for Certificate Revocation; 370 Missing Check for Certificate Revocation after Initial Check | Question 18: operator-supplied CRLs (`with_crls`, `enforce_revocation_expiration`) or a short-lived-certificate policy; the mode is logged | A test where a certificate in a supplied CRL is refused |
| A11 | Protocol or cipher downgrade; unauthenticated key exchange | 757; 322 Key Exchange without Entity Authentication | TLS 1.3 only | A test where a TLS 1.2-only server is refused |
| A12 | Cleartext or HTTP instead of HTTPS | 319; 1428 Reliance on HTTP instead of HTTPS | No plaintext API | Absence by construction; a compile-fail case if an E claim is made |
| A13 | Hanging connect, read or DNS | 1088 Synchronous Access of Remote Resource without Timeout; 400 Uncontrolled Resource Consumption | Default timeouts under the 300 s ceiling. The system resolver cannot be bounded per call, so it runs in a broker with a deadline, or the resolver has its own timeout (question 17) | Tests with an unresponsive server and an unresponsive resolver |
| A14 | Retry or failover loops; amplification | 834 Excessive Iteration; 770 Allocation of Resources Without Limits or Throttling; 405 Asymmetric Resource Consumption (Amplification) | One pass over checked addresses, within one budget | A test where all addresses are unreachable: refused within the budget |
| A15 | Unrestricted bind | 1327 Binding to an Unrestricted IP Address | Bind addresses only from a grant (strategy 7) | A test where an ungranted bind is refused |
| A16 | Trusting a peer by its address | 291 Reliance on IP Address for Authentication | Peers are authenticated by certificate, never by address | Design review |

## 6. Recording and verification

- **When an item is built**, its ledger rows get the mechanism and a proof test in the same change. A CWE claimed as E (for prelude users: A3, A12) needs a corpus case with a matched benign program and the false-rejection rate, as every earlier phase did.
- **The bucket stays unchanged** for rows whose mitigation is policy or operator configuration (A1, A4 to A6, A10), and the strategy stays `tls-net`. No ledger change happens before code and tests exist.
- **Generated docs.** `scripts/residual-map.py` regenerates `docs/residual-cwes.md` from the ledger whenever a row changes.
