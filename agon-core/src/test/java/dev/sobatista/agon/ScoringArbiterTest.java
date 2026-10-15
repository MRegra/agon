package dev.sobatista.agon;

import dev.sobatista.agon.arbiter.ArbiterException;
import dev.sobatista.agon.arbiter.ScoringArbiter;
import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.InMemoryLedger;
import dev.sobatista.agon.message.Receipt;
import dev.sobatista.agon.message.SubmitWriteUp;
import dev.sobatista.agon.model.Challenge;
import dev.sobatista.agon.model.VulnerabilityClass;
import org.junit.jupiter.api.Test;

import static dev.sobatista.agon.model.VulnerabilityClass.SQL_INJECTION;
import static dev.sobatista.agon.model.VulnerabilityClass.XSS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScoringArbiterTest {
    private final Fixtures fx = new Fixtures();

    private ScoringArbiter fresh() {
        return fx.arbiter(new InMemoryLedger());
    }

    /** Publish carol's "login-bypass" (SQL + XSS) so hackers have something to solve. */
    private ScoringArbiter withChallenge() throws ArbiterException {
        ScoringArbiter a = fresh();
        a.publishChallenge(fx.publish("carol", fx.challenge("login-bypass", "carol", SQL_INJECTION, XSS), 1));
        return a;
    }

    @Test
    void happyPathAwardsPointsAndReturnsAVerifiableReceipt() throws Exception {
        ScoringArbiter a = withChallenge();
        Signed<Receipt> receipt = a.submitWriteUp(fx.submit("bob", "login-bypass", SQL_INJECTION, 1));

        assertTrue(receipt.verify(a.publicKey()), "the arbiter signs its receipt");
        assertEquals("red", receipt.payload().group());
        assertEquals(SQL_INJECTION.points(), receipt.payload().reward());
        assertEquals(0, receipt.payload().entryIndex(), "first award is ledger entry 0");
    }

    @Test
    void unknownUserIsRefused() throws Exception {
        ScoringArbiter a = withChallenge();
        // mallory has a key pair but is in neither the directory nor the roster.
        Signed<SubmitWriteUp> m = Signed.sign(
                new SubmitWriteUp("mallory", "login-bypass", SQL_INJECTION, "x", 1), "mallory", fx.priv("mallory"));
        assertEquals(ArbiterException.Reason.UNKNOWN_USER, refusal(() -> a.submitWriteUp(m)));
    }

    @Test
    void impersonationByWrongKeyIsRefused() throws Exception {
        ScoringArbiter a = withChallenge();
        // The envelope claims to be bob, but it is signed with dave's key.
        SubmitWriteUp body = new SubmitWriteUp("bob", "login-bypass", SQL_INJECTION, "x", 1);
        byte[] davesSig = Signed.sign(body, "dave", fx.priv("dave")).signature();
        Signed<SubmitWriteUp> forged = new Signed<>(body, "bob", davesSig);
        assertEquals(ArbiterException.Reason.BAD_SIGNATURE, refusal(() -> a.submitWriteUp(forged)));
    }

    @Test
    void actingAsSomeoneYouAreNotIsRefused() throws Exception {
        ScoringArbiter a = withChallenge();
        // dave signs correctly as dave, but the payload claims bob is the hacker.
        SubmitWriteUp body = new SubmitWriteUp("bob", "login-bypass", SQL_INJECTION, "x", 1);
        Signed<SubmitWriteUp> env = new Signed<>(body, "dave", Signed.sign(body, "dave", fx.priv("dave")).signature());
        assertEquals(ArbiterException.Reason.BAD_SIGNATURE, refusal(() -> a.submitWriteUp(env)));
    }

    @Test
    void aTamperedSubmissionIsRefused() throws Exception {
        ScoringArbiter a = withChallenge();
        Signed<SubmitWriteUp> original = fx.submit("bob", "login-bypass", SQL_INJECTION, 1);
        // A man in the middle flips the vulnerability class but keeps bob's signature.
        SubmitWriteUp flipped = new SubmitWriteUp("bob", "login-bypass", XSS, "an attack on login-bypass", 1);
        Signed<SubmitWriteUp> tampered = new Signed<>(flipped, original.signerId(), original.signature());
        assertEquals(ArbiterException.Reason.BAD_SIGNATURE, refusal(() -> a.submitWriteUp(tampered)));
    }

    @Test
    void replayingAStateChangeIsRefused() throws Exception {
        ScoringArbiter a = withChallenge();
        a.submitWriteUp(fx.submit("bob", "login-bypass", SQL_INJECTION, 1));
        // Same sequence number again — a replay.
        assertEquals(ArbiterException.Reason.STALE_SEQUENCE,
                refusal(() -> a.submitWriteUp(fx.submit("bob", "login-bypass", SQL_INJECTION, 1))));
    }

    @Test
    void aDuplicateReadNonceIsRefused() throws Exception {
        ScoringArbiter a = withChallenge();
        a.scoreboard(fx.query("bob", 42));
        assertEquals(ArbiterException.Reason.DUPLICATE_READ, refusal(() -> a.scoreboard(fx.query("bob", 42))));
    }

    @Test
    void aNonLeaderCannotPublish() {
        ScoringArbiter a = fresh();
        Challenge c = fx.challenge("x", "bob", SQL_INJECTION);
        assertEquals(ArbiterException.Reason.NOT_A_LEADER, refusal(() -> a.publishChallenge(fx.publish("bob", c, 1))));
    }

    @Test
    void publishingAChallengeAuthoredBySomeoneElseIsRefused() {
        ScoringArbiter a = fresh();
        // alice is a leader, but the challenge claims carol as its author.
        Challenge c = fx.challenge("x", "carol", SQL_INJECTION);
        assertEquals(ArbiterException.Reason.AUTHOR_MISMATCH, refusal(() -> a.publishChallenge(fx.publish("alice", c, 1))));
    }

    @Test
    void publishingTheSameChallengeTwiceIsRefused() throws Exception {
        ScoringArbiter a = withChallenge();
        Challenge again = fx.challenge("login-bypass", "carol", SQL_INJECTION);
        assertEquals(ArbiterException.Reason.CHALLENGE_EXISTS, refusal(() -> a.publishChallenge(fx.publish("carol", again, 2))));
    }

    @Test
    void aWriteUpForAnUnknownChallengeIsRefused() {
        ScoringArbiter a = fresh();
        assertEquals(ArbiterException.Reason.UNKNOWN_CHALLENGE,
                refusal(() -> a.submitWriteUp(fx.submit("bob", "nope", SQL_INJECTION, 1))));
    }

    @Test
    void aWriteUpForAClassTheChallengeLacksIsRefused() throws Exception {
        ScoringArbiter a = fresh();
        a.publishChallenge(fx.publish("carol", fx.challenge("sqli-only", "carol", SQL_INJECTION), 1));
        assertEquals(ArbiterException.Reason.VULN_NOT_IN_CHALLENGE,
                refusal(() -> a.submitWriteUp(fx.submit("bob", "sqli-only", XSS, 1))));
    }

    @Test
    void aLeaderCannotScoreTheirOwnChallenge() throws Exception {
        ScoringArbiter a = withChallenge();
        // carol already used sequence 1 to publish, so her self-score attempt uses a fresh sequence.
        assertEquals(ArbiterException.Reason.SELF_SCORING,
                refusal(() -> a.submitWriteUp(fx.submit("carol", "login-bypass", SQL_INJECTION, 2))));
    }

    @Test
    void solvingTheSameClassTwiceIsRefused() throws Exception {
        ScoringArbiter a = withChallenge();
        a.submitWriteUp(fx.submit("bob", "login-bypass", SQL_INJECTION, 1));
        assertEquals(ArbiterException.Reason.ALREADY_SOLVED,
                refusal(() -> a.submitWriteUp(fx.submit("bob", "login-bypass", SQL_INJECTION, 2))));
    }

    /** Run something that should be refused and return the reason, failing the test if it was accepted. */
    private static ArbiterException.Reason refusal(ThrowingRun action) {
        ArbiterException e = assertThrows(ArbiterException.class, action::run);
        return e.reason();
    }

    @FunctionalInterface
    private interface ThrowingRun {
        void run() throws Exception;
    }
}
