---
title: "I rebuilt another college project. This one is a scoreboard nobody has to trust."
subtitle: "What it means to keep score for a hacking competition when nobody trusts the referee — and the one-line bug in my old code that scored people at random. (Agon, part 1.)"
tags: [security, java, cryptography, digital-signatures, ctf]
status: draft
date: 2026-10-15
series: Agon
part: 1
---

A few years ago, for a network-and-systems-security class, a group of us built a **scoreboard**. Not for football —
for a capture-the-flag competition. Group leaders published little vulnerable programs ("challenges"), other people
found the bugs and wrote them up, and a central server handed out points. It worked well enough to pass, and then it
sat in a repo.

I dug it back up, threw the old code away, and rebuilt it in Java from scratch — because the best way I know to
actually understand a thing is to build it and then explain it to you. So here we are again.

## What is a scoreboard, as a security problem?

Picture a competition. There are **hackers**, split into **groups**. Some hackers are **leaders**, and a leader can
publish a **challenge** — a program with a known vulnerability in it. Any hacker can submit a **write-up**: "I found
a SQL injection in `login-bypass`, here's how." If they're right, their group gets points.

One server — call it the **arbiter** — keeps the board. And here's the whole problem in one sentence: *everyone has
a reason to lie to it, and it has a reason to lie to everyone.* A hacker wants points they didn't earn. A leader
wants their own group to win. And the arbiter itself — whoever runs it — could quietly bump a friend's score and
nobody would know. In a real competition, "trust me, the score is right" is not good enough.

So the job isn't really "add up numbers." It's: make every claim and every award **provable**, so that no one — not
a hacker, not a leader, not even the arbiter — can cheat without getting caught.

## A signature is a claim you can't take back

The tool for that is a digital signature. Each user has a private key only they hold and a public key everyone has.
When they sign a message, anyone can check — with their public key — that it was really them and that not one byte
has changed. They can't deny it later, and nobody can forge it.

In Agon every message that crosses a boundary is wrapped in a `Signed<T>`:

```java
public record Signed<T extends Signable>(T payload, String signerId, byte[] signature) {
    public static <T extends Signable> Signed<T> sign(T payload, String signerId, PrivateKey key) {
        return new Signed<>(payload, signerId, Signatures.sign(key, payload.canonicalBytes()));
    }
    public boolean verify(PublicKey key) {
        return Signatures.verify(key, payload.canonicalBytes(), signature);
    }
}
```

A submission is signed by the hacker. An award is signed by the arbiter and handed back as a `Receipt`, so the
hacker holds proof the points were given — forever, without asking the arbiter again. That's non-repudiation, and it
falls out of one `verify` call.

## The one-line mistake I'm glad I found

Here's the bug in the old code that I think about more than I'd like to admit. When a challenge was published, the
server decided which *kind* of vulnerability it contained — buffer overflow, SQL injection, XSS — like this:

```java
String[] vulnTypes = { "Buffer Overflow", "Code Injection", "SQL Ijnection", /* ... */ "XSS" };
int n = rand.nextInt(8);
sda.challengeHasVuln(vulnTypes[n], challengeName);
```

It picked the vulnerability **at random**. (Typos and all — "SQL Ijnection" is really in there.) So the points a
write-up earned had nothing to do with what the hacker actually found. The scoreboard was keeping score of a game
nobody was really playing.

In Agon, a challenge *declares* the classes it really contains, and the signature covers them:

```java
public record PublishChallenge(String leaderId, Challenge challenge, long sequence) implements Signable {
    public byte[] canonicalBytes() {
        return Bytes.of("PublishChallenge", leaderId, challenge.name(), /* ... */,
                classesOf(challenge), sequence);   // the exact vulnerability set is IN the signed bytes
    }
}
```

A write-up is then accepted — and scored — only for a class that challenge actually has. No randomness, no
guessing: the score reflects the finding, and the leader signed off on exactly which findings count.

`Bytes.of` joins fields with a separator so `of("a","bc")` and `of("ab","c")` can never collide — a real signing
pitfall. The signature covers the type, the parties, the challenge, the vulnerability set *and* the sequence number.
Change any of them and `verify` returns false.

## So what

Right now that's a scoreboard you can talk to: signed submissions in, signed receipts out, and a `verify` that
catches anyone who lies about who they are or what they found. A few hundred lines, covered by tests I trust, and you
can run it today.

Next post: the part I'm proudest of — making the **board itself** impossible to quietly edit, by turning it into a
hash-chained ledger. Because a signature stops a hacker from lying to the arbiter; it doesn't stop the arbiter from
lying to everyone else.

The code is here: **[github.com/MRegra/agon](https://github.com/MRegra/agon)**. Apache-2.0, built to be read. It
started life as a project I half-understood at 22. Funny how that keeps happening.
