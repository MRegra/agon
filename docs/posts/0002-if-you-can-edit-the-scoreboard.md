---
title: "If you can edit the scoreboard, there is no game"
subtitle: "The original kept scores as rows in a database. Anyone who could reach the database could win. Here's how a hash chain turns the board into evidence. (Agon, part 2.)"
tags: [security, java, cryptography, hash-chain, tamper-evidence]
status: draft
date: 2026-10-15
series: Agon
part: 2
---

In [part 1](0001-a-scoreboard-nobody-has-to-trust.md) we stopped hackers from lying to the arbiter: every submission
is signed, so you can't claim a bug you didn't find or pretend to be someone else. But there's a bigger liar in the
room, and it's the arbiter.

## The row that wins the game

In the original project the scoreboard lived in a table. Awarding points was an `INSERT`; the board was a `SELECT …
SUM`. Which means the score was whatever the database currently said. Anyone who could reach that database — the
person running the server, a SQL injection somewhere else in the stack, a sloppy backup restore — could set any
group's total to anything, and the board would report it with a straight face. There'd be no trace. In a competition
people care about, that's not a bug in the scoreboard; it *is* the scoreboard, and it belongs to whoever has the
database password.

A signature on each submission doesn't help here. The arbiter is allowed to add points — that's its job. The problem
is that nothing ties the *current total* to the *history of real awards*. The number floats free of its evidence.

## Make the board a replay, not a number

So in Agon the arbiter never stores a total. It stores a **ledger**: an append-only list of awards, and the board is
a *replay* of that ledger. Each award is a `ScoreEntry`:

```java
public record ScoreEntry(long index, String prevHash, String hackerId, String group, String challengeName,
                         VulnerabilityClass vuln, int reward, long hackerSequence) implements Signable {
    public byte[] canonicalBytes() {
        return Bytes.of("ScoreEntry", index, prevHash, hackerId, group, challengeName, vuln.name(),
                reward, hackerSequence);
    }
    public String hash() { return Hashes.sha256Hex(canonicalBytes()); }
}
```

Two fields do the heavy lifting. `index` is the entry's position. `prevHash` is the hash of the entry before it — so
the entries form a chain, each one committing to the entire history behind it. And the arbiter **signs** each entry
(it travels as a `Signed<ScoreEntry>`), with the signature covering `prevHash` and `index` along with everything
else.

Now think about what an attacker has to do to inflate a score:

- **Edit an entry** (change a `reward` from 60 to 1000)? The signature was over the old bytes; it no longer matches.
  And the entry's hash changes, so the *next* entry's `prevHash` is now wrong too. Two breaks for the price of one.
- **Insert a fake award**? They'd have to sign it as the arbiter. They don't have the arbiter's key.
- **Delete or reorder entries**? The chain stops linking, and the indices stop counting 0, 1, 2…

Reading the board is just checking all of that and adding up:

```java
public void verifyOrThrow(PublicKey arbiterKey) {
    String expectedPrev = Hashes.GENESIS;
    long expectedIndex = 0;
    for (Signed<ScoreEntry> signed : ledger.entries()) {
        ScoreEntry e = signed.payload();
        if (e.index() != expectedIndex)        throw new LedgerException(WRONG_INDEX, e.index(), ...);
        if (!e.prevHash().equals(expectedPrev)) throw new LedgerException(BROKEN_CHAIN, e.index(), ...);
        if (!signed.verify(arbiterKey))         throw new LedgerException(BAD_SIGNATURE, e.index(), ...);
        expectedPrev = e.hash();
        expectedIndex++;
    }
}
```

The totals are then a pure fold over the verified entries. The board is no longer a number the server keeps and
could change — it's a *function of signed, chained evidence*. The demo makes the point by flipping one reward and
asking verification what it thinks:

```
Verify every entry against the arbiter's public key: ✓
Flip one reward in the ledger and verify again: ✗ rejected (tamper detected)
```

## What this does and doesn't buy you

It does *not* stop the arbiter from refusing to answer, or from stopping the competition. Integrity is not
availability. A single arbiter can still go down or sulk — that's why a replicated arbiter is on the roadmap.

What it buys is this: the arbiter — or anyone who gets to the storage — **cannot lie about the score without being
caught by anyone who kept a copy of the ledger.** It can't invent a `100`, and it can't make a real award disappear.
The game stops being "trust whoever has the database" and becomes "check the math." For a competition, that's the
whole difference between a scoreboard and a rumour.

Next post: replay. A signed submission is real — so what stops me from sending the *same* real submission again, and
again, and collecting the points each time?

Code: **[github.com/MRegra/agon](https://github.com/MRegra/agon)**.
