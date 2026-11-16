# Design note: the listener capability (Phase 6, batch 6)

Status: **L1 to L4 decided (owner, 2026-11-16, the recommendation on all four).** Spec section 8, question 25. This implements the program side of the exchange gateway's Q6 contract (`gateway-proposal.md`): the gateway forwards each request over a Unix domain socket with `Authorization: Bearer <Corten token>`. It also closes the part of the missing-capabilities row (`phase-6.md`) about listening sockets; the clock, UDP and outgoing Unix sockets stay open there.

## What it is for

A checked program cannot accept a connection today: the checker bans `TcpListener`, `UnixListener` and `UnixStream`, and `corten-std` offers nothing in their place. So no Corten program can serve the requests the gateway authenticates. The listener is that capability, shaped so that the request handler never runs for an unauthenticated caller.

## Decisions (owner, 2026-11-16)

- **L1. The program creates its socket from a grant.** A manifest line `listen NAME unix PATH authn AUTHN` grants one socket at `PATH`. `Capabilities::load` binds it, as it opens every other grant. Rejected: the launcher binds and passes the descriptor (systemd style). That would only work under the launcher, and would add descriptor passing in two places.
- **L2. Only authenticated requests reach the program.** `AUTHN` must name an `authn` grant in the same manifest, or the manifest is refused. `corten-std` checks each request's Bearer token with that grant's keys before the handler runs. The handler receives the `Authenticated` principal and the request; a missing or refused token gets 401 and runs no program code. Rejected: raw requests, where each handler calls the authenticator and can forget to.
- **L3. hyper parses HTTP, HTTP/1.1 only.** It is the parser the gateway already uses, fuzzed upstream; `corten-std` sets every limit. The added crates go through the Phase 5 review (below). Rejected: a new strict parser in `corten-std`, which would be hand-written parsing on the program's trust boundary; and streams only, which would leave L2 unenforceable.
- **L4. A synchronous handler; `corten-std` runs the runtime.** `listener.serve(handler, log)` takes a plain function from `(&Authenticated, Request)` to `Response`. `corten-std` owns the runtime, the concurrency cap, the timeouts and the size limits, so a program author writes no async code. Rejected: async handlers, which would expose cancellation and `Send` bounds to every program.

## The contract

- **The grant.** `PATH` is absolute. Its directory must exist, must not be writable by group or others, and must be owned by the program's user. An existing `PATH` is replaced only if it is a socket owned by the program's user (a stale socket from the last run); anything else is refused.
- **Creating the socket.** The directory is opened once without following links (`O_PATH` on Linux, which Landlock does not check) and every later step is relative to that descriptor. The socket is bound under a random name in the same directory, set to mode 0660, starts listening, then is renamed over `PATH`. So no one can connect to it while its mode is still the umask's, and a connection that arrives before the program serves waits in the backlog. The gateway connects through the file mode: run it as the program's user, or in the socket's group.
- **Each request.** The `Authorization` header must be `Bearer ` followed by a token the `authn` grant accepts (`TokenAuthenticator`: signature, audience, expiry, lifetime). The handler sees the method, path, query, the other headers and the body; never the token.
- **Limits.** Request heads at most 64 KiB, read within 10 s; bodies at most 1 MiB (the gateway's own cap), or 413; at most 64 handlers at once, or 503 with `Retry-After`. A handler that panics produces a 500; the panic is logged, and the listener carries on.
- **Logging.** The authenticator logs `authn.ok` or `authn.refused` (never the token). The listener logs `listen.request` with the method, the status and the principal, and `listen.panic`; it does not log paths or queries, which can carry personal data.
- **The sandbox.** `corten-sandbox` lets the program create and replace a socket in the grant's directory, and nothing else there (Landlock `MakeSock` and `RemoveFile` on that directory).
- **The checker.** `UnixListener`, `UnixStream` and `TcpListener` stay banned in checked programs; the ban's reason now names the `listen` grant.

## Phase 5 review of the added crates

Recorded in `phase-6.md` when the change lands: the crates `corten-std` gains, measured with `cargo tree` before and after, and `cargo deny` over the result.

## What it cannot claim

- It does not authenticate the gateway as a process: any local user who can connect to the socket and holds a valid token is served. File permissions on the socket and its directory decide who can connect.
- The handler runs to completion even when its caller has gone; a synchronous function cannot be cancelled.
