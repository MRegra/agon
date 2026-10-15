package dev.sobatista.agon.server;

import dev.sobatista.agon.arbiter.ScoringArbiter;
import dev.sobatista.agon.crypto.Signatures;
import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.Ledger;
import dev.sobatista.agon.message.PublishChallenge;
import dev.sobatista.agon.message.SubmitWriteUp;
import dev.sobatista.agon.model.Challenge;
import dev.sobatista.agon.model.KeyDirectory;
import dev.sobatista.agon.model.Roster;
import dev.sobatista.agon.model.VulnerabilityClass;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** The same fixed cast as the core tests, re-declared for the server module's test scope. */
final class ServerFixtures {
    private static final Map<String, KeyPair> KEYS = new HashMap<>();

    final KeyPair arbiterKeys = keyPair("arbiter");
    final Roster roster = Roster.builder()
            .member("alice", "red", true).member("bob", "red")
            .member("carol", "blue", true).member("dave", "blue")
            .build();
    final KeyDirectory directory = KeyDirectory.builder()
            .add("alice", keyPair("alice").getPublic()).add("bob", keyPair("bob").getPublic())
            .add("carol", keyPair("carol").getPublic()).add("dave", keyPair("dave").getPublic())
            .build();

    ScoringArbiter arbiter(Ledger ledger) {
        return new ScoringArbiter("arbiter", arbiterKeys, directory, roster, ledger);
    }

    static synchronized KeyPair keyPair(String id) {
        return KEYS.computeIfAbsent(id, k -> Signatures.generateRsa(1024));
    }

    PrivateKey priv(String id) {
        return keyPair(id).getPrivate();
    }

    Challenge challenge(String name, String author, VulnerabilityClass... vulns) {
        return new Challenge(name, "a " + name + " challenge", "/" + name, author, Set.of(vulns));
    }

    Signed<PublishChallenge> publish(String leader, Challenge challenge, long seq) {
        return Signed.sign(new PublishChallenge(leader, challenge, seq), leader, priv(leader));
    }

    Signed<SubmitWriteUp> submit(String hacker, String ch, VulnerabilityClass vuln, long seq) {
        return Signed.sign(new SubmitWriteUp(hacker, ch, vuln, "attack on " + ch, seq), hacker, priv(hacker));
    }
}
