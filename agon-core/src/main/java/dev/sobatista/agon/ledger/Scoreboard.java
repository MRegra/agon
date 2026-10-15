package dev.sobatista.agon.ledger;

import dev.sobatista.agon.crypto.Hashes;
import dev.sobatista.agon.crypto.Signed;

import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * A read-only view over a {@link Ledger}: it verifies the chain and replays it into scores.
 *
 * <p>Nothing here is trusted. {@link #verifyOrThrow} re-derives every link and re-checks every arbiter
 * signature, so a scoreboard loaded from disk — or handed to you by someone — is only believed if its math
 * holds. The totals are a pure replay of the verified entries, which is the whole point: the board is not a
 * number the server keeps and could change, it is a function of signed, chained evidence.
 */
public final class Scoreboard {
    private final Ledger ledger;

    public Scoreboard(Ledger ledger) {
        this.ledger = ledger;
    }

    /**
     * Verify the entire ledger against the arbiter's public key: each entry sits at its own index, links to the
     * previous entry, and is validly signed by the arbiter.
     *
     * @throws LedgerException at the first entry that fails, naming why and where
     */
    public void verifyOrThrow(PublicKey arbiterKey) {
        String expectedPrev = Hashes.GENESIS;
        long expectedIndex = 0;
        for (Signed<ScoreEntry> signed : ledger.entries()) {
            ScoreEntry e = signed.payload();
            if (e.index() != expectedIndex) {
                throw new LedgerException(LedgerException.Reason.WRONG_INDEX, e.index(),
                        "expected index " + expectedIndex);
            }
            if (!e.prevHash().equals(expectedPrev)) {
                throw new LedgerException(LedgerException.Reason.BROKEN_CHAIN, e.index(),
                        "prevHash does not match the previous entry");
            }
            if (!signed.verify(arbiterKey)) {
                throw new LedgerException(LedgerException.Reason.BAD_SIGNATURE, e.index(),
                        "entry is not validly signed by the arbiter");
            }
            expectedPrev = e.hash();
            expectedIndex++;
        }
    }

    /** {@code true} if {@link #verifyOrThrow} would pass. */
    public boolean verifies(PublicKey arbiterKey) {
        try {
            verifyOrThrow(arbiterKey);
            return true;
        } catch (LedgerException e) {
            return false;
        }
    }

    /** Points per group, highest first — the scoreboard as people read it. */
    public Map<String, Integer> totalsByGroup() {
        return rank(replay(ScoreEntry::group));
    }

    /** Points per hacker, highest first. */
    public Map<String, Integer> totalsByHacker() {
        return rank(replay(ScoreEntry::hackerId));
    }

    /** The set of {@code hacker|challenge|vuln} keys already awarded — the arbiter rebuilds its state from this. */
    public Set<String> solvedKeys() {
        Set<String> solved = new TreeSet<>();
        for (Signed<ScoreEntry> s : ledger.entries()) {
            solved.add(s.payload().solvedKey());
        }
        return solved;
    }

    private Map<String, Integer> replay(java.util.function.Function<ScoreEntry, String> key) {
        Map<String, Integer> totals = new TreeMap<>();
        for (Signed<ScoreEntry> s : ledger.entries()) {
            ScoreEntry e = s.payload();
            totals.merge(key.apply(e), e.reward(), Integer::sum);
        }
        return totals;
    }

    private static Map<String, Integer> rank(Map<String, Integer> totals) {
        List<Map.Entry<String, Integer>> rows = new java.util.ArrayList<>(totals.entrySet());
        rows.sort(Map.Entry.<String, Integer>comparingByValue().reversed()
                .thenComparing(Map.Entry.comparingByKey()));
        Map<String, Integer> ordered = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> row : rows) {
            ordered.put(row.getKey(), row.getValue());
        }
        return ordered;
    }
}
