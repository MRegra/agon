# Provenance

Agon began as a university *Network and Computer Systems Security* assignment at IST ("SIRS", a secure scoring
system for a capture-the-flag competition). This repository is a **clean-room Java 21 reimplementation and
expansion** written from an understanding of the problem, not a port of any prior code.

- The original group's Java solution, its database scripts and the course's assignment/report material are **not**
  included here — they are third-party / course material and stay out of the public tree (kept locally under a
  git-ignored `reference/`).
- All code in this repository is original work, licensed under [Apache-2.0](LICENSE).
- The operations and security properties Agon targets are described in our own words in [docs/SPEC.md](docs/SPEC.md).

Agon also *finishes* what the original left undone or did unsafely:

- **Scoring that reflects the finding.** The original assigned each challenge a vulnerability type **at random**
  on the server (`vulnTypes[rand.nextInt(8)]`), so the points a write-up earned had nothing to do with what the
  hacker actually exploited. In Agon a challenge declares the classes it really contains, and a write-up is only
  accepted — and scored — for a class that challenge has.
- **Replay protection that holds.** The original authenticated requests with a signed, timestamped envelope and a
  client-side proof of work. Agon binds a **monotonic sequence number into the signed bytes** of every
  state-changing request (a one-time nonce for reads) and validates the **Proof of Work server-side**, bound to the
  request's exact bytes.
- **A scoreboard you can audit.** The original kept scores as plain database rows that whoever held the database
  could change. Agon records every award as a **signed, hash-chained ledger entry**; the scoreboard is a replay
  anyone can re-verify against the arbiter's public key.

Agon is its own project now: a teaching-first, tamper-evident competition scoreboard.
