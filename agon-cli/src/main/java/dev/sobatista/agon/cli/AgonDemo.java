package dev.sobatista.agon.cli;

import dev.sobatista.agon.arbiter.ArbiterException;
import dev.sobatista.agon.arbiter.ScoringArbiter;
import dev.sobatista.agon.crypto.Signatures;
import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.InMemoryLedger;
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
import dev.sobatista.agon.model.VulnerabilityClass;
import dev.sobatista.agon.pow.ProofOfWork;
import dev.sobatista.agon.server.AdmissionException;
import dev.sobatista.agon.server.GuardedArbiter;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Runs a whole competition in one process: two groups, a leader each, hackers submitting signed write-ups
 * through a Proof-of-Work gate, and a scoreboard that is printed and then verified from its signed, chained
 * entries. No network, no database — the quickest way to watch the thing work.
 */
public final class AgonDemo {
    /** Lighter than the server default so the demo mints quickly; still a real proof of work. */
    private static final int DEMO_DIFFICULTY = 16;

    public static void main(String[] args) {
        Result r = new AgonDemo().run();
        if (!r.verified) {
            throw new IllegalStateException("the scoreboard failed to verify — this should never happen");
        }
    }

    record Result(Map<String, Integer> byGroup, Map<String, Integer> byHacker,
                  boolean verified, boolean tamperDetected) {}

    private final Map<String, Player> players = new LinkedHashMap<>();
    private GuardedArbiter arbiter;
    private Ledger ledger;

    Result run() {
        System.out.println("agon — a scoreboard nobody has to trust\n");

        // Two groups; one leader each. Keys are made per player; the directory holds only public keys.
        player("alice", "red", true);
        player("bob", "red", false);
        player("carol", "blue", true);
        player("dave", "blue", false);

        Roster roster = Roster.builder()
                .member("alice", "red", true).member("bob", "red")
                .member("carol", "blue", true).member("dave", "blue")
                .build();
        KeyDirectory keys = directory();

        KeyPair arbiterKeys = Signatures.generateRsa(1024);
        this.ledger = new InMemoryLedger();
        ScoringArbiter core = new ScoringArbiter("arbiter", arbiterKeys, keys, roster, ledger);
        this.arbiter = new GuardedArbiter(core, DEMO_DIFFICULTY);

        System.out.println("Leaders publish challenges (each declares the vulnerability classes it really has):");
        publish("alice", new Challenge("heartbleed-lab", "a leaky TLS heartbeat", "memory.c:heartbeat",
                "alice", Set.of(VulnerabilityClass.BUFFER_OVERFLOW, VulnerabilityClass.HEAP_OVERFLOW)));
        publish("carol", new Challenge("login-bypass", "a login form that trusts its input", "/login",
                "carol", Set.of(VulnerabilityClass.SQL_INJECTION, VulnerabilityClass.XSS)));

        System.out.println("\nHackers submit signed write-ups (points go to the hacker's group):");
        submit("bob", "login-bypass", VulnerabilityClass.SQL_INJECTION, "' OR '1'='1 on the username field");
        Signed<SubmitWriteUp> bobsFirst = lastSubmission;      // keep it to replay later
        submit("dave", "heartbleed-lab", VulnerabilityClass.BUFFER_OVERFLOW, "read past the heartbeat length");
        submit("bob", "login-bypass", VulnerabilityClass.XSS, "<script> in the error message");

        System.out.println("\nThings the arbiter refuses (and why):");
        refuse("alice scoring her own challenge", () ->
                submitRaw("alice", "heartbleed-lab", VulnerabilityClass.HEAP_OVERFLOW, "nope"));
        refuse("a write-up for a class the challenge does not have", () ->
                submitRaw("dave", "login-bypass", VulnerabilityClass.BUFFER_OVERFLOW, "wrong class"));
        refuse("dave impersonating bob (right id, wrong key)", this::daveForgingAsBob);
        refuse("bob replaying his accepted SQL write-up", () -> arbiter.submitWriteUp(bobsFirst, workFor(bobsFirst.payload())));
        refuse("a submission with no Proof of Work", () -> {
            Signed<SubmitWriteUp> s = sign(players.get("dave"),
                    new SubmitWriteUp("dave", "heartbleed-lab", VulnerabilityClass.HEAP_OVERFLOW, "x", 99));
            arbiter.submitWriteUp(s, null);
        });

        Scoreboard board = readScoreboard("carol");
        Map<String, Integer> byGroup = board.totalsByGroup();
        Map<String, Integer> byHacker = board.totalsByHacker();

        System.out.println("\nScoreboard (a pure replay of the signed ledger):");
        System.out.println("  by group:  " + byGroup);
        System.out.println("  by hacker: " + byHacker);

        boolean verified = board.verifies(arbiter.publicKey());
        System.out.println("\nVerify every entry against the arbiter's public key: " + (verified ? "✓" : "✗"));

        boolean tamperDetected = !new Scoreboard(tamperReward(ledger)).verifies(arbiter.publicKey());
        System.out.println("Flip one reward in the ledger and verify again: "
                + (tamperDetected ? "✗ rejected (tamper detected)" : "accepted — BUG"));

        return new Result(byGroup, byHacker, verified, tamperDetected);
    }

    // --- acting as players ----------------------------------------------------------------------------------

    private Signed<SubmitWriteUp> lastSubmission;

    private void publish(String leader, Challenge challenge) {
        Player p = players.get(leader);
        PublishChallenge body = new PublishChallenge(leader, challenge, p.nextSequence());
        Signed<PublishChallenge> signed = sign(p, body);
        try {
            arbiter.publishChallenge(signed, workFor(body));
            System.out.printf("  %-6s published %-14s classes=%s%n", leader, challenge.name(), challenge.classes());
        } catch (ArbiterException | AdmissionException e) {
            System.out.println("  unexpected refusal: " + e.getMessage());
        }
    }

    private void submit(String hacker, String challenge, VulnerabilityClass vuln, String description) {
        try {
            Signed<Receipt> receipt = submitRaw(hacker, challenge, vuln, description);
            Receipt r = receipt.payload();
            System.out.printf("  %-6s solved %-14s %-16s +%d -> %s (ledger #%d)%n",
                    hacker, challenge, vuln, r.reward(), r.group(), r.entryIndex());
        } catch (ArbiterException | AdmissionException e) {
            System.out.println("  unexpected refusal for " + hacker + ": " + e.getMessage());
        }
    }

    private Signed<Receipt> submitRaw(String hacker, String challenge, VulnerabilityClass vuln, String description)
            throws ArbiterException, AdmissionException {
        Player p = players.get(hacker);
        SubmitWriteUp body = new SubmitWriteUp(hacker, challenge, vuln, description, p.nextSequence());
        Signed<SubmitWriteUp> signed = sign(p, body);
        lastSubmission = signed;
        return arbiter.submitWriteUp(signed, workFor(body));
    }

    private void daveForgingAsBob() throws ArbiterException, AdmissionException {
        // The envelope claims to be from bob, but it is signed with dave's key.
        SubmitWriteUp body = new SubmitWriteUp("bob", "login-bypass", VulnerabilityClass.SQL_INJECTION, "forged", 50);
        byte[] davesSignature = Signed.sign(body, "dave", players.get("dave").keys.getPrivate()).signature();
        Signed<SubmitWriteUp> forged = new Signed<>(body, "bob", davesSignature);
        arbiter.submitWriteUp(forged, workFor(body));
    }

    private Scoreboard readScoreboard(String reader) {
        Player p = players.get(reader);
        Signed<ScoreQuery> q = sign(p, new ScoreQuery(reader, System.nanoTime()));
        try {
            return arbiter.scoreboard(q);
        } catch (ArbiterException e) {
            throw new IllegalStateException(e);
        }
    }

    private void refuse(String what, ThrowingRun action) {
        try {
            action.run();
            System.out.println("  " + what + ": ACCEPTED — BUG");
        } catch (ArbiterException e) {
            System.out.println("  " + what + ": refused (" + e.reason() + ")");
        } catch (AdmissionException e) {
            System.out.println("  " + what + ": refused (" + e.reason() + ")");
        } catch (Exception e) {
            System.out.println("  " + what + ": refused (" + e.getMessage() + ")");
        }
    }

    // --- helpers --------------------------------------------------------------------------------------------

    private void player(String id, String group, boolean leader) {
        players.put(id, new Player(id, group, leader, Signatures.generateRsa(1024)));
    }

    private KeyDirectory directory() {
        KeyDirectory.Builder b = KeyDirectory.builder();
        players.values().forEach(p -> b.add(p.id, p.keys.getPublic()));
        return b.build();
    }

    private <T extends dev.sobatista.agon.crypto.Signable> Signed<T> sign(Player p, T body) {
        return Signed.sign(body, p.id, p.keys.getPrivate());
    }

    private ProofOfWork workFor(dev.sobatista.agon.crypto.Signable request) {
        return ProofOfWork.mint(request.canonicalBytes(), DEMO_DIFFICULTY);
    }

    /** A read-only ledger view with the first entry's reward altered but its signature kept — to prove it fails. */
    private static Ledger tamperReward(Ledger original) {
        List<Signed<ScoreEntry>> entries = new ArrayList<>(original.entries());
        Signed<ScoreEntry> first = entries.get(0);
        ScoreEntry e = first.payload();
        ScoreEntry inflated = new ScoreEntry(e.index(), e.prevHash(), e.hackerId(), e.group(),
                e.challengeName(), e.vuln(), e.reward() + 1000, e.hackerSequence());
        entries.set(0, new Signed<>(inflated, first.signerId(), first.signature()));
        return new FrozenLedger(entries);
    }

    private record FrozenLedger(List<Signed<ScoreEntry>> entries) implements Ledger {
        @Override public void append(Signed<ScoreEntry> entry) { throw new UnsupportedOperationException(); }
        @Override public long size() { return entries.size(); }
    }

    private static final class Player {
        final String id;
        final String group;
        final boolean leader;
        final KeyPair keys;
        private long sequence = 0;

        Player(String id, String group, boolean leader, KeyPair keys) {
            this.id = id;
            this.group = group;
            this.leader = leader;
            this.keys = keys;
        }

        long nextSequence() {
            return ++sequence;
        }
    }

    @FunctionalInterface
    private interface ThrowingRun {
        void run() throws Exception;
    }
}
