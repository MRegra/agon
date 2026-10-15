# Examples

## The in-process competition (no setup)

```bash
mvn install
mvn -q -pl agon-cli exec:java
```

Two groups (`red`, `blue`) with a leader each. The leaders publish two challenges; hackers submit signed write-ups
through a Proof-of-Work gate; the demo then prints the submissions the arbiter refuses, replays the scoreboard, and
flips one reward in the ledger to show verification rejecting it. The source is `agon-cli/.../AgonDemo.java`.

What the demo shows, step by step:

```
G: red  = alice (leader), bob
G: blue = carol (leader), dave

alice -> publishChallenge(heartbleed-lab : BUFFER_OVERFLOW, HEAP_OVERFLOW)
carol -> publishChallenge(login-bypass   : SQL_INJECTION, XSS)

bob  -> submitWriteUp(login-bypass, SQL_INJECTION)  -> +60 to red,  ledger #0
dave -> submitWriteUp(heartbleed-lab, BUFFER_OVERFLOW) -> +80 to blue, ledger #1
bob  -> submitWriteUp(login-bypass, XSS)            -> +40 to red,  ledger #2

scoreboard: red=100, blue=80   (verified against the arbiter's public key ✓)
```

A `Receipt` is signed by the arbiter — verify it any time with the arbiter's public key, without asking the arbiter
again. And the whole scoreboard verifies from its signed, chained entries: that is the receipt the system exists to
produce.

## Building something on top

`agon-core` has no dependencies beyond the JDK, so you can embed a `ScoringArbiter` directly:

```java
Ledger ledger = new FileLedger(Path.of("storage/agon.log"));   // durable, or new InMemoryLedger() for a test
ScoringArbiter arbiter = new ScoringArbiter("arbiter", arbiterKeys, directory, roster, ledger);
GuardedArbiter guarded = new GuardedArbiter(arbiter);          // demand Proof of Work on writes
```
