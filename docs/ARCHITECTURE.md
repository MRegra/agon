# Agon — architecture

Agon is three layers, each a Maven module, each usable on its own. The split keeps the interesting security code
away from durability and runnable plumbing.

```
                 clients (a leader's / hacker's app, AgonDemo)
                          │  Signed<PublishChallenge> · Signed<SubmitWriteUp> · Signed<ScoreQuery> · ProofOfWork
        ┌─────────────────┴───────────────────────────────┐
        │ agon-server  GuardedArbiter (Proof-of-Work gate) · FileLedger (durable) · PublicKeyStore (PKI) │
        └─────────────────┬───────────────────────────────┘
                          │  verified request  ·  append(Signed<ScoreEntry>)
        ┌─────────────────┴───────────────────────────────┐
        │ agon-core    ScoringArbiter  (rules + replay protection + signing)                     │
        │              Scoreboard / Ledger  (hash-chained, signed ScoreEntry — the tamper-evident part) │
        │              Signed<T> · canonical Bytes · Hashes · ProofOfWork · Challenge / Roster / KeyDirectory │
        └──────────────────────────────────────────────────┘
```

## agon-core — the arbiter and the ledger

The heart is `ScoringArbiter`. Before it does anything with a request it **authenticates** it: the acting user must
be known to the `KeyDirectory` and `Roster`, the envelope must be signed *as* that user (not merely by someone), and
the signature must verify against the directory's key for that user. That one method is where impersonation, forgery
and tampering all fail. Then it checks the **sequence number** is strictly newer than the last it accepted from that
user (reads use a remembered nonce instead), and only then applies the domain rules.

`Signed<T>` is the only thing that crosses a boundary. It signs `T.canonicalBytes()`, an explicit field-by-field
encoding (`Bytes.of(...)`, unit-separated so `of("a","bc")` and `of("ab","c")` can't collide), so the signature
covers the sequence number and every field, not an opaque blob. The original project signed a fixed-length substring
of a request string; a field outside that window went unsigned. Here the message, not an offset, decides what the
signature covers.

The **scoreboard is a ledger**, and that is the design idea worth the whole project. Every accepted write-up becomes
a `ScoreEntry` carrying its `index` and the `prevHash` of the entry before it; the arbiter signs it into a
`Signed<ScoreEntry>` and appends it. The entries form a hash chain, and each signature covers `prevHash` and `index`,
so an entry cannot be moved, dropped, duplicated or edited without breaking either the chain or a signature.
`Scoreboard` is a read-only view: `verifyOrThrow` re-derives every link and re-checks every arbiter signature, and
the totals are a pure replay. The board is therefore not a number the server keeps and could change — it is a
function of signed, chained evidence. A dishonest arbiter can refuse to answer, but it cannot forge a `100` or make a
real award disappear without anyone who kept a copy of the ledger noticing.

## agon-server — making it durable and runnable

`FileLedger` is the scoreboard's write-ahead log: each entry is one serialized, Base64, newline-terminated line, and
an append **fsyncs before it returns**, so a confirmed award is on disk. An award lost to a crash before the fsync
simply never happened. On startup the ledger replays every complete line (stopping at a torn tail — the fingerprint
of a crash mid-write) and the arbiter rebuilds its "already solved" set and each hacker's sequence watermark *from
the ledger*, so a restarted server refuses replays and double-awards exactly as before. Because the append-time link
check runs on reload too, a file whose middle was edited fails to load as a valid chain.

`GuardedArbiter` is an admission gate: every state-changing request must carry a `ProofOfWork` stamp bound to the
request's exact bytes and meeting a minimum difficulty, checked in a single hash before the arbiter does any work.
Minting costs the client ~`2^difficulty` hashes; checking is one; and a stamp minted for one submission can't be
reused for another. Reads are free. `PublicKeyStore` is the PKI's job reduced to its essence: a directory of public
keys on disk from which a `KeyDirectory` is built.

## agon-cli — making it visible

`AgonDemo` wires a whole competition in-process — two groups, a leader each, hackers submitting through the
Proof-of-Work gate — and then does three things on purpose: prints the submissions the arbiter *refuses* and why,
replays the scoreboard, and flips one reward in the ledger to show verification catching it. No network, no database;
the quickest way to see the mechanism.

## Why the seams are where they are

`Arbiter` (the operation API), `Ledger` (append-only signed storage) and `Signed<ScoreEntry>` (the chained record)
are the interfaces everything plugs into. Swapping the in-memory ledger for the file-backed one is a constructor
argument; a networked arbiter is the same `ScoringArbiter` behind a transport instead of a direct call, which is why
it lands on the roadmap without a rewrite of the rules or the ledger.
