package dev.sobatista.agon.ledger;

import dev.sobatista.agon.crypto.Hashes;
import dev.sobatista.agon.crypto.Signed;

import java.util.List;

/**
 * Append-only storage for the signed, hash-chained scoreboard entries.
 *
 * <p>The ledger enforces only the structural invariant on append — an entry's index is the next position and
 * its {@code prevHash} is the current head. It does <em>not</em> check signatures or scoring rules; that is the
 * arbiter's job before it appends, and {@link Scoreboard#verifyOrThrow} re-checks everything independently when
 * reading a ledger back (including one loaded from disk, which the arbiter never signed in this process).
 */
public interface Ledger {

    /**
     * Append the next entry.
     *
     * @throws LedgerException if the entry's index or prevHash does not continue the chain
     */
    void append(Signed<ScoreEntry> entry);

    List<Signed<ScoreEntry>> entries();

    long size();

    /** Hex hash of the last entry, or {@link Hashes#GENESIS} when the ledger is empty. */
    default String head() {
        List<Signed<ScoreEntry>> all = entries();
        return all.isEmpty() ? Hashes.GENESIS : all.get(all.size() - 1).payload().hash();
    }

    /** Shared append-time invariant check for implementations. */
    static void checkLink(Ledger ledger, Signed<ScoreEntry> entry) {
        long expectedIndex = ledger.size();
        if (entry.payload().index() != expectedIndex) {
            throw new LedgerException(LedgerException.Reason.WRONG_INDEX, entry.payload().index(),
                    "expected index " + expectedIndex);
        }
        if (!entry.payload().prevHash().equals(ledger.head())) {
            throw new LedgerException(LedgerException.Reason.BROKEN_CHAIN, entry.payload().index(),
                    "prevHash does not match the current head");
        }
    }
}
