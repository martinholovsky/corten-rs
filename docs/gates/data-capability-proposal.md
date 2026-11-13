# Data capability: a database grant whose lookups are checked (design note, 2026-11-14)

Status: **proposed; owner decisions needed on Q1 to Q4** (below). Spec section 8, question 24 schedules it with batch 6. It is the item that delivers CWE-566 (authorization bypass through a user-controlled SQL primary key), which stays planned on the chart because of it. Nothing here is built.

## What it is for

`corten-std` has typed SQL text (`sql!`, which closes injection) but no way to reach a database: the checker bans the network and process APIs a client would use. A program that needs a database today must admit a client crate through its dependency policy. That leaves CWE-566 fully writable: fetch a row by the id in the request, never asking whether this user may see it.

The capability gives programs a database connection from a signed manifest grant. On a grant marked `protected`, every row a query touches is filtered by who is asking. The program cannot choose to skip that.

## Proposed shape (for the prototype)

```text
db NAME HOST:PORT DATABASE ROLE CLIENT-CERT-PATH [protected]
```

- **Connection.** TLS 1.3 to the database, using `NetCap`'s address checks and timeouts and the platform's roots.
  - The program authenticates to the database with a TLS client certificate (PostgreSQL's `cert` method), not a password. This applies question 23's rule to the program's own credential: the key file is named in the signed manifest, and the sandbox grants it read-only.
- **Queries.** Only `sql!` text with bound parameters. There is no raw-string query API.
- **A `protected` grant.**
  - A query runs only inside `db.transaction(&who)`, which takes an `Authenticated` principal. Its first statement sets the principal for that transaction: `SET LOCAL`, through `set_config(..., true)` with a bound parameter. The database's row-level security policies filter every row by it.
  - At connect time the prelude refuses, before any data flows, a role that bypasses row-level security (`rolbypassrls`, `rolsuper`). It also refuses any table named in the grant whose `relforcerowsecurity` is off, so the policies apply even to the table's owner.
  - Every transaction logs the principal and the grant. The rows are the program's data and are not logged.

## What it can and cannot claim

- **CWE-566 (and CWE-639 for database rows):** every row a protected query touches is filtered by the principal's policy, whatever key the request supplied. Whether the policy is *right* stays C, the same split as step 1's `Policy`. Whether "filtered on every lookup" meets the E bar is question 24's to settle after the prototype's corpus run, as question 14 requires.
- **SQL injection** is already closed by `sql!`; this capability adds no new claim there.
- **Trusted base:** the database's row-level security is a new trusted-base assumption, listed in `tcb.md` when built. So is the client library.

## Questions for the owner

**Q1. Where is the check enforced?**
- **A. In the database, through row-level security, with the prelude making it unavoidable (recommended).** The prelude sets the principal on every transaction, refuses bypassing roles and unforced tables, and offers no other query path.
  - **Pros:** it checks every query, including ones the program writes later, and keeps one source of truth for access.
  - **Cons:** PostgreSQL only. Policies are SQL that the operator or program must get right.
- B. In the prelude, through typed lookups: a protected query takes its key only from an `Authorized` proof, as `ProtectedDir` does.
  - **Pros:** independent of the database engine.
  - **Cons:** it covers only lookups by one key. Joins, searches and reports escape it, or need a typed query language: a large API, and against design principle 1.
- C. Both. B adds friction and little protection beyond A.

**Q2. Which client library?**
- **A. `postgres` / `tokio-postgres` 0.19.14 / 0.7.18 (MIT OR Apache-2.0) (recommended).** Small, maintained, and on `tokio`, which the prelude already carries for name resolution. Its TLS goes through `rustls`, as `NetCap` does.
- B. `sqlx` 0.9.0 (MIT OR Apache-2.0). Larger. Its compile-time query checks need a live database at build time, which the hermetic build forbids.
- Either way: the Phase 5 review (licences, advisories, package count) before adoption.

**Q3. How does the program authenticate to the database?**
- **A. A TLS client certificate only (recommended),** per question 23. The deployer issues one per program from a dedicated client CA.
- B. Also SCRAM passwords, for databases that cannot do `cert`. Weaker, and a password in the deployment again.

**Q4. Which databases?**
- **PostgreSQL first and only for the prototype (recommended).** Its row-level security is what Q1 A rests on. Others are added only when each has an equivalent mechanism, recorded per engine in the ledger.

## Prototype plan (after the answers, with batch 6)

1. Phase 5 review of the client library; record the measurement in `phase-6.md`.
2. `corten_std::db`: the grant, a TLS client-certificate connection, `sql!`-only queries, `transaction(&who)`, and the connect-time refusals. Unit tests, plus a mutation per control (no principal set, a bypassing role accepted, an unforced table accepted), each shown to fail a test.
3. Linux tests against PostgreSQL in a container: rows of another principal are not returned for a request that supplies their key, and the same query through a plain client (the control) returns them.
4. Corpus cases for CWE-566: a `good.rs` querying through a protected grant, and bad variants that query without a principal, through a raw client crate (refused by the dependency policy), or build the statement from a string. Then the full corpus run, and only then question 24's bucket decision.
