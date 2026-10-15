package dev.sobatista.agon;

import dev.sobatista.agon.arbiter.ScoringArbiter;
import dev.sobatista.agon.crypto.Signatures;
import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.Ledger;
import dev.sobatista.agon.message.PublishChallenge;
import dev.sobatista.agon.message.ScoreQuery;
import dev.sobatista.agon.message.SubmitWriteUp;
import dev.sobatista.agon.model.Challenge;
import dev.sobatista.agon.model.KeyDirectory;
import dev.sobatista.agon.model.Roster;
import dev.sobatista.agon.model.VulnerabilityClass;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Shared test scaffolding: keys for a fixed cast, the directory and roster that know them, and small factory
 * methods for the signed requests. Keys are cached across tests — they carry no state, and 1024-bit keygen is
 * the slow part. "mallory" has a key pair but is in neither the roster nor the directory: she is the unknown.
 */
public final class Fixtures {
    public static final String ARBITER = "arbiter";

    private static final Map<String, KeyPair> KEYS = new HashMap<>();

    public final KeyPair arbiterKeys = keyPair(ARBITER);
    public final Roster roster = Roster.builder()
            .member("alice", "red", true).member("bob", "red")
            .member("carol", "blue", true).member("dave", "blue")
            .build();
    public final KeyDirectory directory = KeyDirectory.builder()
            .add("alice", pub("alice")).add("bob", pub("bob"))
            .add("carol", pub("carol")).add("dave", pub("dave"))
            .build();

    public ScoringArbiter arbiter(Ledger ledger) {
        return new ScoringArbiter(ARBITER, arbiterKeys, directory, roster, ledger);
    }

    public static synchronized KeyPair keyPair(String id) {
        return KEYS.computeIfAbsent(id, k -> Signatures.generateRsa(1024));
    }

    public PublicKey pub(String id) {
        return keyPair(id).getPublic();
    }

    public PrivateKey priv(String id) {
        return keyPair(id).getPrivate();
    }

    public Challenge challenge(String name, String author, VulnerabilityClass... vulns) {
        return new Challenge(name, "a " + name + " challenge", "/" + name, author, Set.of(vulns));
    }

    public Signed<PublishChallenge> publish(String leader, Challenge challenge, long seq) {
        return Signed.sign(new PublishChallenge(leader, challenge, seq), leader, priv(leader));
    }

    public Signed<SubmitWriteUp> submit(String hacker, String ch, VulnerabilityClass vuln, long seq) {
        return Signed.sign(new SubmitWriteUp(hacker, ch, vuln, "an attack on " + ch, seq), hacker, priv(hacker));
    }

    public Signed<ScoreQuery> query(String reader, long nonce) {
        return Signed.sign(new ScoreQuery(reader, nonce), reader, priv(reader));
    }
}
