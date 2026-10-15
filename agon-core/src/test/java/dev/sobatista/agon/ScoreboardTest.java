package dev.sobatista.agon;

import dev.sobatista.agon.arbiter.ScoringArbiter;
import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.InMemoryLedger;
import dev.sobatista.agon.ledger.Ledger;
import dev.sobatista.agon.ledger.LedgerException;
import dev.sobatista.agon.ledger.ScoreEntry;
import dev.sobatista.agon.ledger.Scoreboard;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static dev.sobatista.agon.model.VulnerabilityClass.SQL_INJECTION;
import static dev.sobatista.agon.model.VulnerabilityClass.XSS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScoreboardTest {
    private final Fixtures fx = new Fixtures();

    /** A genuine ledger: carol publishes, bob solves both classes. Two chained, signed entries. */
    private InMemoryLedger genuineLedger() throws Exception {
        InMemoryLedger ledger = new InMemoryLedger();
        ScoringArbiter a = fx.arbiter(ledger);
        a.publishChallenge(fx.publish("carol", fx.challenge("login-bypass", "carol", SQL_INJECTION, XSS), 1));
        a.submitWriteUp(fx.submit("bob", "login-bypass", SQL_INJECTION, 1));
        a.submitWriteUp(fx.submit("bob", "login-bypass", XSS, 2));
        return ledger;
    }

    @Test
    void totalsAreAPureReplayOfTheEntries() throws Exception {
        Scoreboard board = new Scoreboard(genuineLedger());
        assertEquals(SQL_INJECTION.points() + XSS.points(), board.totalsByGroup().get("red"));
        assertEquals(SQL_INJECTION.points() + XSS.points(), board.totalsByHacker().get("bob"));
        assertEquals(2, board.solvedKeys().size());
    }

    @Test
    void aGenuineLedgerVerifies() throws Exception {
        assertTrue(new Scoreboard(genuineLedger()).verifies(fx.arbiterKeys.getPublic()));
    }

    @Test
    void tamperingWithARewardBreaksTheSignature() throws Exception {
        List<Signed<ScoreEntry>> entries = new ArrayList<>(genuineLedger().entries());
        Signed<ScoreEntry> first = entries.get(0);
        ScoreEntry e = first.payload();
        ScoreEntry inflated = new ScoreEntry(e.index(), e.prevHash(), e.hackerId(), e.group(),
                e.challengeName(), e.vuln(), 9999, e.hackerSequence());
        entries.set(0, new Signed<>(inflated, first.signerId(), first.signature()));

        LedgerException ex = assertThrows(LedgerException.class,
                () -> new Scoreboard(frozen(entries)).verifyOrThrow(fx.arbiterKeys.getPublic()));
        assertEquals(LedgerException.Reason.BAD_SIGNATURE, ex.reason());
        assertEquals(0, ex.index());
    }

    @Test
    void droppingAnEntryBreaksTheChain() throws Exception {
        List<Signed<ScoreEntry>> entries = new ArrayList<>(genuineLedger().entries());
        entries.remove(0);   // now the surviving entry still claims index 1
        assertFalse(new Scoreboard(frozen(entries)).verifies(fx.arbiterKeys.getPublic()));
    }

    @Test
    void verifyingAgainstTheWrongKeyFails() throws Exception {
        assertFalse(new Scoreboard(genuineLedger()).verifies(fx.pub("alice")));
    }

    @Test
    void appendingOutOfOrderIsRejected() throws Exception {
        InMemoryLedger ledger = genuineLedger();
        Signed<ScoreEntry> replayOfFirst = ledger.entries().get(0);
        LedgerException ex = assertThrows(LedgerException.class, () -> ledger.append(replayOfFirst));
        assertEquals(LedgerException.Reason.WRONG_INDEX, ex.reason());
    }

    private static Ledger frozen(List<Signed<ScoreEntry>> entries) {
        List<Signed<ScoreEntry>> snapshot = Collections.unmodifiableList(new ArrayList<>(entries));
        return new Ledger() {
            @Override public void append(Signed<ScoreEntry> entry) { throw new UnsupportedOperationException(); }
            @Override public List<Signed<ScoreEntry>> entries() { return snapshot; }
            @Override public long size() { return snapshot.size(); }
        };
    }
}
