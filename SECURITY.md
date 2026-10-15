# Security Policy

## Supported versions
Agon is pre-1.0; only the latest `0.x` release gets fixes.

## Reporting a vulnerability
Please **do not** open a public issue for a vulnerability. Email **sobatistacyber@gmail.com** with details and a
proof of concept if you have one. You'll get an acknowledgement within a few days.

## Scope and threat model
Agon is a **teaching** implementation of a tamper-evident competition scoreboard. Its *application* threat model is
the interesting part and is taken seriously: forged or replayed submissions, impersonation, message tampering,
scoring a vulnerability a challenge does not contain, a leader scoring their own challenge, double-scoring, a crash
mid-award, request floods (Proof of Work), and — the point of the project — a scoreboard that has been edited after
the fact. All of these are defended and tested.

What Agon is **not** yet is networked. The arbiter and the demo run in-process, so there is no wire protocol,
serialization endpoint or transport to harden — and nothing here should be exposed on a network as-is. When the
networked arbiter lands (see the [roadmap](ROADMAP.md)), the transport will need the usual care: authenticated
channels, a safe wire format rather than Java serialization, and input limits.

A single arbiter is a single point of failure for **availability** and a single point of trust for *liveness* — but
not for *integrity*: a dishonest arbiter cannot forge an award or hide one, because the scoreboard is a signed,
hash-chained ledger anyone can verify. Replicating the arbiter behind a quorum, so it can't withhold or equivocate
either, is on the roadmap. Demo keys are 1024-bit RSA for speed and are generated in-process; neither is a
production choice.
