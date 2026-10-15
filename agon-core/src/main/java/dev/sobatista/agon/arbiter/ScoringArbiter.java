package dev.sobatista.agon.arbiter;

import dev.sobatista.agon.crypto.Signable;
import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.Ledger;
import dev.sobatista.agon.ledger.ScoreEntry;
import dev.sobatista.agon.ledger.Scoreboard;
import dev.sobatista.agon.message.PublishChallenge;
import dev.sobatista.agon.message.Receipt;
import dev.sobatista.agon.message.ScoreQuery;
import dev.sobatista.agon.message.SubmitWriteUp;
import dev.sobatista.agon.model.Challenge;
import dev.sobatista.agon.model.KeyDirectory;
import dev.sobatista.agon.model.Roster;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The reference arbiter: it verifies every signed request, enforces the scoring rules, and appends accepted
 * awards to a tamper-evident ledger it signs. It is the heart of Agon — small enough to read top to bottom.
 *
 * <p>State kept here is of two kinds. The <strong>awards</strong> live in the {@link Ledger}, which is the
 * durable, signed record; on construction the arbiter rebuilds its "already solved" set and each hacker's
 * sequence watermark <em>from the ledger</em>, so a server that reloads a stored ledger refuses replays and
 * double-awards exactly as before a restart. The challenge registry, leader sequence watermarks and read
 * nonces are per-session competition setup (see {@code docs/SPEC.md}).
 *
 * <p>Not thread-safe by itself; the server wraps it. Keeping the locking out here keeps the rules readable.
 */
public final class ScoringArbiter implements Arbiter {

    private final String arbiterId;
    private final PrivateKey signingKey;
    private final PublicKey publicKey;
    private final KeyDirectory keys;
    private final Roster roster;
    private final Ledger ledger;

    private final Map<String, Challenge> challenges = new HashMap<>();
    private final Map<String, Long> lastSequence = new HashMap<>();   // user -> last accepted sequence
    private final Map<String, Set<Long>> seenNonces = new HashMap<>(); // reader -> nonces used
    private final Set<String> solved = new HashSet<>();                // hacker|challenge|vuln

    public ScoringArbiter(String arbiterId, KeyPair arbiterKeys, KeyDirectory keys, Roster roster, Ledger ledger) {
        this.arbiterId = arbiterId;
        this.signingKey = arbiterKeys.getPrivate();
        this.publicKey = arbiterKeys.getPublic();
        this.keys = keys;
        this.roster = roster;
        this.ledger = ledger;
        rebuildFromLedger();
    }

    /** Rebuild the award-side invariants (solved set, hacker watermarks) from the durable ledger. */
    private void rebuildFromLedger() {
        for (Signed<ScoreEntry> signed : ledger.entries()) {
            ScoreEntry e = signed.payload();
            solved.add(e.solvedKey());
            lastSequence.merge(e.hackerId(), e.hackerSequence(), Math::max);
        }
    }

    @Override
    public Challenge publishChallenge(Signed<PublishChallenge> request) throws ArbiterException {
        PublishChallenge body = request.payload();
        authenticate(request, body.leaderId());
        requireFreshSequence(body.leaderId(), body.sequence());

        if (!roster.isLeader(body.leaderId())) {
            throw new ArbiterException(ArbiterException.Reason.NOT_A_LEADER);
        }
        Challenge challenge = body.challenge();
        if (!challenge.authorId().equals(body.leaderId())) {
            throw new ArbiterException(ArbiterException.Reason.AUTHOR_MISMATCH);
        }
        if (challenges.containsKey(challenge.name())) {
            throw new ArbiterException(ArbiterException.Reason.CHALLENGE_EXISTS);
        }

        challenges.put(challenge.name(), challenge);
        accept(body.leaderId(), body.sequence());
        return challenge;
    }

    @Override
    public Signed<Receipt> submitWriteUp(Signed<SubmitWriteUp> request) throws ArbiterException {
        SubmitWriteUp body = request.payload();
        authenticate(request, body.hackerId());
        requireFreshSequence(body.hackerId(), body.sequence());

        Challenge challenge = challenges.get(body.challengeName());
        if (challenge == null) {
            throw new ArbiterException(ArbiterException.Reason.UNKNOWN_CHALLENGE);
        }
        if (!challenge.contains(body.vuln())) {
            throw new ArbiterException(ArbiterException.Reason.VULN_NOT_IN_CHALLENGE);
        }
        if (challenge.authorId().equals(body.hackerId())) {
            throw new ArbiterException(ArbiterException.Reason.SELF_SCORING);
        }
        String solvedKey = body.hackerId() + "\u001f" + body.challengeName() + "\u001f" + body.vuln().name();
        if (solved.contains(solvedKey)) {
            throw new ArbiterException(ArbiterException.Reason.ALREADY_SOLVED);
        }

        String group = roster.groupOf(body.hackerId());
        int reward = body.vuln().points();
        ScoreEntry entry = new ScoreEntry(ledger.size(), ledger.head(), body.hackerId(), group,
                body.challengeName(), body.vuln(), reward, body.sequence());
        Signed<ScoreEntry> signedEntry = sign(entry);
        ledger.append(signedEntry);

        solved.add(solvedKey);
        accept(body.hackerId(), body.sequence());
        return sign(new Receipt(body.hackerId(), group, body.challengeName(), body.vuln(), reward,
                entry.index(), entry.hash()));
    }

    @Override
    public Scoreboard scoreboard(Signed<ScoreQuery> request) throws ArbiterException {
        ScoreQuery body = request.payload();
        authenticate(request, body.readerId());
        if (!seenNonces.computeIfAbsent(body.readerId(), k -> new HashSet<>()).add(body.nonce())) {
            throw new ArbiterException(ArbiterException.Reason.DUPLICATE_READ);
        }
        return new Scoreboard(ledger);
    }

    @Override
    public PublicKey publicKey() {
        return publicKey;
    }

    /** The id this arbiter signs as — recorded as the signer of every ledger entry and receipt. */
    public String id() {
        return arbiterId;
    }

    // --- the checks every state change shares ---------------------------------------------------------------

    /**
     * The acting user must be known, must be the one who signed the envelope, and the signature must verify
     * against that user's public key. This is where impersonation, forgery and tampering all fail.
     */
    private void authenticate(Signed<?> request, String actor) throws ArbiterException {
        if (!keys.knows(actor) || !roster.knows(actor)) {
            throw new ArbiterException(ArbiterException.Reason.UNKNOWN_USER);
        }
        if (!request.signerId().equals(actor)) {
            throw new ArbiterException(ArbiterException.Reason.BAD_SIGNATURE); // acting as someone you are not
        }
        if (!request.verify(keys.keyOf(actor))) {
            throw new ArbiterException(ArbiterException.Reason.BAD_SIGNATURE); // forged or tampered
        }
    }

    private void requireFreshSequence(String user, long sequence) throws ArbiterException {
        if (sequence <= lastSequence.getOrDefault(user, 0L)) {
            throw new ArbiterException(ArbiterException.Reason.STALE_SEQUENCE);
        }
    }

    private void accept(String user, long sequence) {
        lastSequence.put(user, sequence);
    }

    private <T extends Signable> Signed<T> sign(T payload) {
        return Signed.sign(payload, arbiterId, signingKey);
    }
}
