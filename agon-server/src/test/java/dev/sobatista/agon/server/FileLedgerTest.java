package dev.sobatista.agon.server;

import dev.sobatista.agon.arbiter.ArbiterException;
import dev.sobatista.agon.arbiter.ScoringArbiter;
import dev.sobatista.agon.ledger.LedgerException;
import dev.sobatista.agon.ledger.Scoreboard;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static dev.sobatista.agon.model.VulnerabilityClass.SQL_INJECTION;
import static dev.sobatista.agon.model.VulnerabilityClass.XSS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileLedgerTest {
    private final ServerFixtures fx = new ServerFixtures();

    /** Write a genuine two-award ledger to {@code file} through a real arbiter. */
    private void writeGenuineLedger(Path file) throws ArbiterException {
        ScoringArbiter a = fx.arbiter(new FileLedger(file));
        a.publishChallenge(fx.publish("carol", fx.challenge("login-bypass", "carol", SQL_INJECTION, XSS), 1));
        a.submitWriteUp(fx.submit("bob", "login-bypass", SQL_INJECTION, 1));
        a.submitWriteUp(fx.submit("bob", "login-bypass", XSS, 2));
    }

    @Test
    void awardsSurviveAReopenAndStillVerify(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("ledger.log");
        writeGenuineLedger(file);

        FileLedger reopened = new FileLedger(file);
        assertEquals(2, reopened.size());
        assertTrue(new Scoreboard(reopened).verifies(fx.arbiterKeys.getPublic()));
    }

    @Test
    void aTornTailLineIsIgnoredOnReopen(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("ledger.log");
        writeGenuineLedger(file);
        // Simulate a crash mid-append: a partial line with no terminating newline.
        Files.writeString(file, "halfwrittenbase64garbage", StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);

        assertEquals(2, new FileLedger(file).size(), "the torn tail is dropped, the good entries survive");
    }

    @Test
    void anArbiterRebuiltOnAReloadedLedgerStillRefusesReplaysAndDoubleAwards(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("ledger.log");
        writeGenuineLedger(file);

        // A fresh arbiter over the reloaded ledger — as if the server restarted.
        ScoringArbiter restarted = fx.arbiter(new FileLedger(file));
        // The hacker sequence watermark was rebuilt from the ledger: replaying bob's seq 1 is stale.
        ArbiterException replay = assertThrows(ArbiterException.class,
                () -> restarted.submitWriteUp(fx.submit("bob", "login-bypass", SQL_INJECTION, 1)));
        assertEquals(ArbiterException.Reason.STALE_SEQUENCE, replay.reason());

        // Re-register the challenge (setup is not in the ledger) and try to double-award: the solved set was rebuilt.
        restarted.publishChallenge(fx.publish("carol", fx.challenge("login-bypass", "carol", SQL_INJECTION, XSS), 1));
        ArbiterException dup = assertThrows(ArbiterException.class,
                () -> restarted.submitWriteUp(fx.submit("bob", "login-bypass", SQL_INJECTION, 3)));
        assertEquals(ArbiterException.Reason.ALREADY_SOLVED, dup.reason());
    }

    @Test
    void aReorderedFileFailsToReloadAsAChain(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("ledger.log");
        writeGenuineLedger(file);

        // Swap the two serialized lines; the chain no longer links on reload.
        List<String> lines = Files.readAllLines(file);
        assertEquals(2, lines.size());
        Path reordered = dir.resolve("reordered.log");
        Files.writeString(reordered, lines.get(1) + "\n" + lines.get(0) + "\n");

        assertThrows(LedgerException.class, () -> new FileLedger(reordered));
    }
}
