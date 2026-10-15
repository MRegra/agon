package dev.sobatista.agon.message;

import dev.sobatista.agon.crypto.Bytes;
import dev.sobatista.agon.crypto.Signable;
import dev.sobatista.agon.model.Challenge;
import dev.sobatista.agon.model.VulnerabilityClass;

import java.util.StringJoiner;

/**
 * A group leader publishes a challenge. State-changing, so it carries the leader's monotonic {@code sequence}
 * for replay protection, and the signature covers the whole challenge — including the exact set of
 * vulnerability classes it is worth points for.
 */
public record PublishChallenge(String leaderId, Challenge challenge, long sequence) implements Signable {

    @Override
    public byte[] canonicalBytes() {
        StringJoiner classes = new StringJoiner(",");
        for (VulnerabilityClass v : challenge.classes()) {
            classes.add(v.name());   // challenge() sorts the set deterministically
        }
        return Bytes.of("PublishChallenge", leaderId, challenge.name(), challenge.description(),
                challenge.location(), challenge.authorId(), classes.toString(), sequence);
    }
}
