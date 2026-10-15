# Contributing to Agon

Thanks for looking! Agon is a teaching-first project about authenticated, tamper-evident systems, so clear code and
clear explanations both count as contributions.

## Build & test
Requires **JDK 21** and **Maven 3.9+**.

```bash
mvn verify        # build + run all tests
mvn install       # build the modules into ~/.m2 (needed before exec:java below)
```

Run the in-process competition demo (no network, no database):

```bash
mvn -q -pl agon-cli exec:java
```

## How it's laid out
- `agon-core` — the domain and its security: signed canonical messages, challenges and vulnerability classes, the
  hash-chained scoreboard ledger, Proof of Work, and the arbiter with all the rules. Start here.
- `agon-server` — the runnable authority: the durable crash-safe ledger, the public-key store (the PKI's job), and
  the Proof-of-Work admission guard.
- `agon-cli` — the in-process demo.

## Sending a change
1. Branch from `main`.
2. Keep the change small and focused. Add a test — a bug fix gets a test that fails without it.
3. Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`; `feat!:` or a `BREAKING CHANGE:` footer for anything that breaks the public API.
4. `mvn verify` is green.
5. Open a PR describing what and why.

By contributing you agree your work is licensed under the project's [Apache-2.0](LICENSE) license.

## Style
Readable over clever. This code is also documentation — someone should be able to learn the protocol by reading it.
Comments explain *why*, not *what*. Anything that signs, hashes or verifies spells out exactly which bytes it covers.
