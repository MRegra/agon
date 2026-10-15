# Agon

**A scoreboard nobody has to trust — in Java, built to be read.**

[![CI](https://github.com/MRegra/agon/actions/workflows/ci.yml/badge.svg)](https://github.com/MRegra/agon/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![status](https://img.shields.io/badge/status-0.1.0%20(pre--1.0)-orange)

An *agon* (ἀγών) is a contest. Agon keeps the score of one: a capture-the-flag competition where group **leaders**
publish vulnerability **challenges** and **hackers** submit **write-ups** proving they found a bug, earning points
for their group. A single authority — the **arbiter** — checks every submission and keeps the board.

The catch with "a single authority keeps the board" is that you have to trust it. Agon doesn't ask you to. Every
submission is signed by the hacker; every award the arbiter makes is a **signed entry in a hash-chained ledger**;
and the scoreboard is a **pure replay** of that ledger, not a number the server keeps. Anyone can verify the whole
board from the signed entries — the arbiter can't quietly invent or revoke points, and a hacker can neither forge an
award nor deny one they earned. It's a teaching-first codebase: the goal is that you can read it and learn how
signatures, replay protection and tamper-evident logs actually fit together.

## 30-second demo

Requires JDK 21 and Maven.

```bash
mvn install                       # build the modules
mvn -q -pl agon-cli exec:java     # run a whole competition in one process
```

Two groups, a leader each, hackers submitting signed write-ups through a Proof-of-Work gate:

```
agon — a scoreboard nobody has to trust

Leaders publish challenges (each declares the vulnerability classes it really has):
  alice  published heartbleed-lab classes=[BUFFER_OVERFLOW, HEAP_OVERFLOW]
  carol  published login-bypass   classes=[SQL_INJECTION, XSS]

Hackers submit signed write-ups (points go to the hacker's group):
  bob    solved login-bypass   SQL_INJECTION    +60 -> red (ledger #0)
  dave   solved heartbleed-lab BUFFER_OVERFLOW  +80 -> blue (ledger #1)
  bob    solved login-bypass   XSS              +40 -> red (ledger #2)

Things the arbiter refuses (and why):
  alice scoring her own challenge: refused (SELF_SCORING)
  a write-up for a class the challenge does not have: refused (VULN_NOT_IN_CHALLENGE)
  dave impersonating bob (right id, wrong key): refused (BAD_SIGNATURE)
  bob replaying his accepted SQL write-up: refused (STALE_SEQUENCE)
  a submission with no Proof of Work: refused (MISSING)

Scoreboard (a pure replay of the signed ledger):
  by group:  {red=100, blue=80}
  by hacker: {bob=100, dave=80}

Verify every entry against the arbiter's public key: ✓
Flip one reward in the ledger and verify again: ✗ rejected (tamper detected)
```

## The operations

```java
// a leader publishes a challenge; the signature covers the exact set of vulnerability classes it is worth points for
arbiter.publishChallenge(sign(new PublishChallenge("carol",
        new Challenge("login-bypass", "...", "/login", "carol", Set.of(SQL_INJECTION, XSS)), seq)), proofOfWork);

// a hacker submits a signed write-up; on acceptance the arbiter signs a receipt and appends a ledger entry
Signed<Receipt> receipt = arbiter.submitWriteUp(
        sign(new SubmitWriteUp("bob", "login-bypass", SQL_INJECTION, "' OR '1'='1", seq)), proofOfWork);
receipt.verify(arbiterPublicKey);                         // non-repudiable proof the points were awarded

// the scoreboard is a view over the ledger — verify the whole thing from the signed, chained entries
Scoreboard board = arbiter.scoreboard(sign(new ScoreQuery("bob", nonce)));
board.verifyOrThrow(arbiterPublicKey);                    // every signature + every chain link
board.totalsByGroup();                                    // {red=100, blue=80}
```

Every message is a `Signed<T>` — a payload plus a signature over its **canonical bytes**, so the signature covers
every field that matters (the user, the challenge, the vulnerability class *and* the sequence number). Change one
byte and verification fails.

| Protection | How |
|---|---|
| **Impersonation** | a request must be signed by exactly the user it claims to be from, verified against that user's key in the directory |
| **Tampering (MITM)** | the signature is over canonical bytes, so any change — even flipping the vulnerability class — breaks it |
| **Replay / duplication** | each state-changing request carries the user's monotonic sequence number; reads carry a one-time nonce |
| **Wrong scoring** | a write-up is accepted only for a class the challenge actually has, never by the challenge's own author, never twice for the same class |
| **A lying scoreboard** | every award is a signed, hash-chained ledger entry; the board is a replay anyone can re-verify, so points can't be invented or revoked silently |
| **Request floods (DoS)** | a Proof-of-Work stamp, bound to the request's bytes and validated server-side |
| **Lost-to-a-crash awards** | an award is fsync'd to the ledger *before* the receipt is returned; what isn't durable never happened |

## Modules

| Module | What's inside |
|---|---|
| **agon-core** | The domain and its security — `Signed<T>` over canonical `Bytes`, `VulnerabilityClass` and `Challenge`, the hash-chained `ScoreEntry`/`Scoreboard` ledger, `ProofOfWork`, and the `ScoringArbiter` with all the rules. Start here. |
| **agon-server** | The runnable authority — a durable, crash-safe `FileLedger` (the scoreboard's write-ahead log), the `PublicKeyStore` (the PKI's job), and the `GuardedArbiter` that demands a valid Proof of Work before the arbiter does any work. |
| **agon-cli** | The `AgonDemo` — a whole competition wired in-process, including the submissions that get refused and a ledger tamper that verification catches. |

## How it works

Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design, [`docs/SPEC.md`](docs/SPEC.md) for the exact
operations, security properties and fault model, and [`ROADMAP.md`](ROADMAP.md) for what's next (a networked arbiter,
multiple arbiters a quorum has to agree, a challenge log). Write-ups that explain the ideas live in
[`docs/posts/`](docs/posts).

## Status & scope

Pre-1.0: the API can still move. This is a **teaching implementation**. The *application* threat model — forgery,
impersonation, tampering, replay, wrong or double scoring, a lying scoreboard, crashes and request floods — is
defended and tested (37 tests). What it is **not** yet is networked: the arbiter and the demo run in-process, so
there is no wire protocol or transport hardening to attack. A single arbiter is also still a single point of trust
for *availability* (not for integrity — that's what the signed ledger is for); replicating it behind a quorum is on
the [roadmap](ROADMAP.md). Demo keys are 1024-bit RSA for speed — not a production choice (see [SECURITY.md](SECURITY.md)).

## Provenance

Agon grew out of a university network-and-systems-security assignment (IST, "SIRS", a secure CTF scoring system).
It is a clean-room Java reimplementation and expansion — the original code is not included — and it *finishes* three
things that project left undone: real per-challenge vulnerability scoring (the original assigned a **random**
vulnerability type), sequence-number replay protection with a request-bound server-validated Proof of Work (the
original leaned on a timestamp window and a client-side proof), and a **tamper-evident** scoreboard (the original's
scores were plain database rows). See [PROVENANCE.md](PROVENANCE.md).

## License

[Apache-2.0](LICENSE).
