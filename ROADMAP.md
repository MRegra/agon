# Roadmap

Agon is built in layers so each milestone is a self-contained thing to learn and to write about.

## Shipped in 0.1.0
- The secure arbiter: signed submissions, a PKI-backed public-key directory, per-user sequence numbers and one-time
  read nonces (replay/duplication), impersonation and tamper prevention, and the scoring rules (a write-up scores
  only for a class the challenge has, never by the author, never twice).
- A **tamper-evident scoreboard**: every award is a signed, hash-chained `ScoreEntry`; the board is a pure replay
  that `verifyOrThrow` re-checks end to end.
- **Durability**: a crash-safe `FileLedger` fsync'd before each receipt, replayed on startup, with a torn tail
  ignored; the arbiter rebuilds its "already solved" set and sequence watermarks from the reloaded ledger.
- **Proof-of-Work anti-spam** with server-side validation, bound to each request's bytes.
- An in-process demo and 37 core/server/cli tests.

## Next
- **A networked arbiter** — a wire protocol so clients and the arbiter are real separate processes, with a safe
  serialization format and authenticated channels (0.1.0 runs in-process; this makes it a service). *(post: "Putting the arbiter on the network without putting it at risk")*
- **A replicated arbiter** — several arbiters a client's read quorum has to agree on, so no single arbiter can
  withhold or equivocate about the board, only slow it down. *(post: "A scoreboard that survives a lying referee")*
- **A published challenge log** — fold challenge publication into its own signed log so a restart rebuilds the
  challenge set too, not just the awards.
- **Anti-grinding business logic** — diminishing returns, per-group rate caps, and first-blood bonuses, all as
  rules the ledger makes auditable.
- **CI/pipeline polish** — release automation, coverage, spotless/checkstyle. *(post: "Shipping a Java library like you mean it")*
