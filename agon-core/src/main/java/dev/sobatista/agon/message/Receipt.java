package dev.sobatista.agon.message;

import dev.sobatista.agon.crypto.Bytes;
import dev.sobatista.agon.crypto.Signable;
import dev.sobatista.agon.model.VulnerabilityClass;

/**
 * The arbiter's signed acknowledgement that it accepted a write-up and recorded it at a specific place in the
 * ledger. Signed by the arbiter, it is the hacker's non-repudiable proof that the points were awarded:
 * anyone holding the arbiter's public key can verify it, and {@code entryIndex}/{@code chainHead} tie it to
 * the exact, tamper-evident ledger entry (see {@code ledger.Scoreboard}).
 */
public record Receipt(String hackerId, String group, String challengeName, VulnerabilityClass vuln,
                      int reward, long entryIndex, String chainHead) implements Signable {

    @Override
    public byte[] canonicalBytes() {
        return Bytes.of("Receipt", hackerId, group, challengeName, vuln.name(), reward, entryIndex, chainHead);
    }
}
