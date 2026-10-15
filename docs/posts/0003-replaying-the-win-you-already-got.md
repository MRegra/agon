---
title: "Replaying the win you already got"
subtitle: "A signed message is genuine forever — which is exactly the problem. Sequence numbers, nonces, and a proof of work that costs the sender, not the server. (Agon, part 3.)"
tags: [security, java, cryptography, replay-attacks, proof-of-work]
status: draft
date: 2026-10-15
series: Agon
part: 3
---

Here's an attack that trips people up because it uses *no forgery at all*. In [part 1](0001-a-scoreboard-nobody-has-to-trust.md)
we made every submission signed, so you can't fake one. Fine. So I'll capture a real one — yours, say, a perfectly
valid write-up you submitted — and I'll send it again. It's genuinely signed by you. It verifies. Do I get the
points a second time?

If the only check is "is the signature valid?", then yes. A valid signature is valid forever; that's the point of a
signature. Which means it can't, on its own, tell "this is a fresh request" from "this is a recording of an old one."

The original project reached for a **timestamp**: sign the time into the message and reject anything too old. That
narrows the window, but it doesn't close it — inside the window a replay still works, and clocks drift, and you've
now got a liveness knob to tune. I wanted something that's just true or false.

## A counter that lives inside the signature

Agon gives every user a monotonic **sequence number** and — this is the part that matters — puts it *inside the
signed bytes*:

```java
public record SubmitWriteUp(String hackerId, String challengeName, VulnerabilityClass vuln,
                            String attackDescription, long sequence) implements Signable {
    public byte[] canonicalBytes() {
        return Bytes.of("SubmitWriteUp", hackerId, challengeName, vuln.name(), attackDescription, sequence);
    }
}
```

The arbiter remembers the last sequence it accepted from each user and refuses anything not strictly newer:

```java
private void requireFreshSequence(String user, long sequence) throws ArbiterException {
    if (sequence <= lastSequence.getOrDefault(user, 0L)) {
        throw new ArbiterException(Reason.STALE_SEQUENCE);
    }
}
```

Now a replay fails on arithmetic, not timing. Your captured submission carried sequence 7; the arbiter has already
moved to 7; `7 <= 7`, refused. And because the sequence is *in the signed bytes*, I can't just bump it to 8 — that
changes the bytes, and your signature no longer matches. The counter and the signature protect each other.

This is the bug that quietly breaks a lot of real systems: they sign "the content" and keep the anti-replay field
next to it, unsigned. Then the signature is real and the replay defence is a decoration. Here, signing is never
"sign the object" — each message says exactly which bytes it covers, and the sequence is always one of them.

Reads don't change state, so they don't need a counter; they carry a one-time **nonce** the arbiter remembers
instead, so a captured read can't be replayed to probe the board either.

## Making the flood expensive — for the sender

Replay is one hand of denial-of-service; sheer volume is the other. If each request is cheap to send, I can bury the
arbiter in work. So state-changing requests have to carry a **Proof of Work**: a hashcash stamp bound to the exact
bytes of the request.

```java
public record ProofOfWork(long nonce, int difficulty) {
    public static ProofOfWork mint(byte[] request, int difficulty) { /* search for a nonce */ }
    public boolean satisfies(byte[] request) {
        byte[] combined = /* request || nonce */;
        return Hashes.leadingZeroBits(Hashes.sha256(combined)) >= difficulty;
    }
}
```

The asymmetry is the whole idea. Minting a stamp costs the sender roughly `2^difficulty` hashes. **Checking it costs
one hash, and the server does the checking** — against the request's own bytes, before it does any real work. A
stamp minted for one submission can't be reused for another, because the submission's bytes are hashed into it. The
original ran its proof of work on the client only, which is a bit like checking your own ticket; here it's an
admission cost the server actually enforces:

```java
if (pow == null)                               throw new AdmissionException(MISSING);
if (pow.difficulty() < minDifficulty)          throw new AdmissionException(INSUFFICIENT_DIFFICULTY);
if (!pow.satisfies(request.canonicalBytes()))  throw new AdmissionException(INVALID);
```

## Where that leaves us

Three posts in, Agon has: submissions nobody can forge, a scoreboard nobody can quietly edit, replays that fail on a
counter, and a flood that costs the flooder. All of it in-process and tested — 37 tests, including one that captures
a real submission and tries to cash it in twice.

What's left is the network. Right now the arbiter is a method call; making it a service means a wire protocol, a
safe serialization format, and a replicated arbiter so one referee can't hold the game hostage. That's the roadmap,
and the next posts.

Code: **[github.com/MRegra/agon](https://github.com/MRegra/agon)**. Apache-2.0, built to be read.
