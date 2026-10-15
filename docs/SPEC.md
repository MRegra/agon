# Agon — specification

This is what Agon promises, in our own words. It targets the IST SIRS secure-scoring problem; the wording here is
original.

## Entities and state

- A fixed, globally-known set of **users**, each with an RSA key pair. Their public keys live in a `KeyDirectory`
  (the PKI's role). The arbiter has its own key pair too.
- A **roster**: every user belongs to one **group**, and some users are **leaders**. A leader is the only member who
  may publish challenges. Points a hacker earns accrue to the hacker's group.
- A set of **challenges**, each published by a leader. A challenge declares the **vulnerability classes** it
  contains; each class is worth a fixed number of points.
- One logical **arbiter** that verifies submissions and keeps an append-only, hash-chained **ledger** of awards. The
  scoreboard is a replay of that ledger.

Per user the arbiter tracks the last **sequence number** it accepted and the set of read **nonces** seen. Per
`⟨hacker, challenge, class⟩` it tracks whether an award already exists.

## Operations

All requests are signed by their sender; every award and receipt is signed by the arbiter.

- `publishChallenge(PublishChallenge{leader, challenge, sequence})` → `Challenge`
  — a leader publishes a challenge. Refused unless the signer is the named leader, is a leader in the roster, is the
  challenge's declared author, the challenge name is new, and the sequence is fresh.
- `submitWriteUp(SubmitWriteUp{hacker, challenge, vuln, attackDescription, sequence})` → `Signed<Receipt>`
  — a hacker claims a vulnerability class of a challenge. Refused unless the signer is the named hacker, the sequence
  is fresh, the challenge exists, it contains `vuln`, the hacker is not the challenge's author, and no award already
  exists for `⟨hacker, challenge, vuln⟩`. On acceptance the arbiter appends a signed `ScoreEntry` and returns a
  signed `Receipt` referencing it.
- `scoreboard(ScoreQuery{reader, nonce})` → `Scoreboard`
  — an authenticated read. Refused unless the reader is known, signs the request, and the nonce is unused. The
  returned view is verifiable against the arbiter's public key.

State-changing operations additionally require a `ProofOfWork` stamp (see property 8), checked by the server.

## Security properties

1. **Authenticity / non-repudiation.** Every request and every award is signed over the payload's canonical byte
   encoding, which includes every security-relevant field. A `Receipt` and every `ScoreEntry` are verifiable by
   anyone holding the arbiter's public key.
2. **Integrity (no tampering / MITM).** Any change to a signed payload — including flipping the vulnerability class —
   breaks its signature; altered messages are refused.
3. **No impersonation.** A request is accepted only if its signer id equals the acting user named in the payload and
   the signature verifies against that user's public key in the directory.
4. **No replay / duplication.** Each state-changing request carries the user's monotonic `sequence`; the arbiter
   refuses anything not strictly newer than the last it accepted from that user. Reads use a one-time nonce.
5. **Correct scoring only.** Only a leader publishes, and only their own challenge; a write-up scores only for a
   class the challenge actually contains, never for the author's own challenge, and never twice for the same
   `⟨hacker, challenge, class⟩`.
6. **A tamper-evident scoreboard.** Every award is an entry in a hash-chained, arbiter-signed ledger. Verification
   re-derives every link and re-checks every signature, so an entry cannot be inserted, removed, reordered or edited
   without detection, and the totals cannot disagree with the evidence.

## Dependability properties

7. **Crash recovery.** Awards are rebuilt only by replaying a durable ledger. An award is made durable (fsync'd)
   before its receipt is returned, so no confirmed award is lost; a torn tail from a crash mid-write is ignored on
   replay; and the arbiter's "already solved" set and sequence watermarks are rebuilt from the ledger.
8. **DoS resistance.** State-changing requests must carry a Proof of Work bound to the request's bytes and meeting a
   minimum difficulty, checked by the server before it does work.

## Assumptions and non-goals

- The set of users and their roster (groups, leaders) is **fixed and known**; there is no registration or
  membership-change protocol in 0.1.0. Challenge publication is per-session setup and is not itself in the ledger
  (the award ledger is).
- There is **one arbiter**. It cannot forge or hide an award (the ledger is signed and chained), but it is a single
  point of failure for availability; a replicated arbiter is on the roadmap.
- The **transport does not exist yet**: the arbiter runs in-process. There is no wire format or network to harden in
  0.1.0; the networked arbiter and its hardening are on the roadmap.
- Keys are managed out of band; the demo generates them for convenience.
