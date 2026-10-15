# Changelog

All notable changes to Agon are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Agon uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-15
### Added
- `agon-core`: a secure, tamper-evident competition scoreboard.
  - RSA-signed requests and results (`Signed<T>`) over explicit canonical bytes, so a signature covers every
    field including the sequence number — not an opaque blob, the bug the original project shipped.
  - The `ScoringArbiter`: a PKI-backed key directory and roster, per-user monotonic sequence numbers and one-time
    read nonces, impersonation / tamper / replay prevention, and the scoring rules (publish only as a leader and
    only your own challenge; score only a class the challenge has, never your own challenge, never twice).
  - Real per-challenge vulnerability scoring — challenges declare the classes they contain, each worth fixed
    points — replacing the original's random vulnerability assignment.
  - A hash-chained, arbiter-signed `ScoreEntry` ledger and a `Scoreboard` whose totals are a pure replay and whose
    `verifyOrThrow` re-checks every signature and every chain link.
  - `ProofOfWork`: a hashcash stamp bound to a request's exact bytes.
- `agon-server`: a durable write-ahead `FileLedger` (fsync before confirm, replay on startup, torn tail ignored,
  reorder/tamper rejected on reload), the `PublicKeyStore` (the PKI's job), and the `GuardedArbiter` Proof-of-Work
  admission gate with server-side validation.
- `agon-cli`: the in-process `AgonDemo` running a whole competition, the refused submissions, and a ledger tamper
  caught by verification.
- 37 tests across signatures, the attack classes, the scoring rules, ledger verification, crash recovery and Proof
  of Work.

[Unreleased]: https://github.com/MRegra/agon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MRegra/agon/releases/tag/v0.1.0
