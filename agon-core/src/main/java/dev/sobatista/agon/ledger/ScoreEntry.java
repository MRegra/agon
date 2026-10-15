package dev.sobatista.agon.ledger;

import dev.sobatista.agon.crypto.Bytes;
import dev.sobatista.agon.crypto.Hashes;
import dev.sobatista.agon.crypto.Signable;
import dev.sobatista.agon.model.VulnerabilityClass;

/**
 * One award in the scoreboard ledger: a hacker solved a vulnerability class of a challenge and earned points.
 *
 * <p>Each entry carries its {@code index} and the {@code prevHash} of the entry before it, so the entries form
 * a hash chain. The signature (the entry travels as a {@code Signed<ScoreEntry>} signed by the arbiter) covers
 * {@link #canonicalBytes()}, which includes {@code prevHash} and {@code index} — so an entry cannot be moved,
 * dropped, duplicated or edited without breaking either the chain or the signature. That is what makes the
 * scoreboard tamper-evident: in the original, scores were plain rows anyone with the database could change.
 *
 * @param index         position in the ledger, starting at 0
 * @param prevHash      hex SHA-256 of the previous entry's canonical bytes ({@link Hashes#GENESIS} for the first)
 * @param hackerId      the hacker who earned the points
 * @param group         the group the points accrue to
 * @param challengeName the challenge solved
 * @param vuln          the vulnerability class written up
 * @param reward        points awarded (the class's points)
 * @param hackerSequence the hacker's sequence number for the submission, bound in so the award is non-repudiable
 */
public record ScoreEntry(long index, String prevHash, String hackerId, String group, String challengeName,
                         VulnerabilityClass vuln, int reward, long hackerSequence) implements Signable {

    @Override
    public byte[] canonicalBytes() {
        return Bytes.of("ScoreEntry", index, prevHash, hackerId, group, challengeName, vuln.name(),
                reward, hackerSequence);
    }

    /** The hex hash the next entry will reference as its {@code prevHash}. */
    public String hash() {
        return Hashes.sha256Hex(canonicalBytes());
    }

    /** A stable key for "this hacker already solved this class of this challenge". */
    public String solvedKey() {
        return hackerId + "\u001f" + challengeName + "\u001f" + vuln.name();
    }
}
