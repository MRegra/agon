package dev.sobatista.agon.message;

import dev.sobatista.agon.crypto.Bytes;
import dev.sobatista.agon.crypto.Signable;
import dev.sobatista.agon.model.VulnerabilityClass;

/**
 * A hacker submits a write-up claiming they found a particular {@link VulnerabilityClass} in a challenge.
 * State-changing: the {@code sequence} is the hacker's monotonic counter, and it is inside the signed bytes,
 * so a captured submission cannot be replayed with a bumped counter.
 */
public record SubmitWriteUp(String hackerId, String challengeName, VulnerabilityClass vuln,
                            String attackDescription, long sequence) implements Signable {

    @Override
    public byte[] canonicalBytes() {
        return Bytes.of("SubmitWriteUp", hackerId, challengeName, vuln.name(), attackDescription, sequence);
    }
}
