package dev.sobatista.agon.server;

import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.InMemoryLedger;
import dev.sobatista.agon.message.SubmitWriteUp;
import dev.sobatista.agon.pow.ProofOfWork;
import org.junit.jupiter.api.Test;

import static dev.sobatista.agon.model.VulnerabilityClass.SQL_INJECTION;
import static dev.sobatista.agon.model.VulnerabilityClass.XSS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GuardedArbiterTest {
    private static final int MIN = 10;   // low enough to mint instantly in a test
    private final ServerFixtures fx = new ServerFixtures();

    private GuardedArbiter guarded() throws Exception {
        var core = fx.arbiter(new InMemoryLedger());
        core.publishChallenge(fx.publish("carol", fx.challenge("login-bypass", "carol", SQL_INJECTION, XSS), 1));
        return new GuardedArbiter(core, MIN);
    }

    @Test
    void aValidProofOfWorkIsAdmitted() throws Exception {
        GuardedArbiter g = guarded();
        Signed<SubmitWriteUp> req = fx.submit("bob", "login-bypass", SQL_INJECTION, 1);
        ProofOfWork pow = ProofOfWork.mint(req.payload().canonicalBytes(), MIN);
        assertTrue(g.submitWriteUp(req, pow).verify(g.publicKey()));
    }

    @Test
    void aMissingProofOfWorkIsRefused() throws Exception {
        GuardedArbiter g = guarded();
        Signed<SubmitWriteUp> req = fx.submit("bob", "login-bypass", SQL_INJECTION, 1);
        AdmissionException e = assertThrows(AdmissionException.class, () -> g.submitWriteUp(req, null));
        assertEquals(AdmissionException.Reason.MISSING, e.reason());
    }

    @Test
    void anUnderpoweredProofIsRefused() throws Exception {
        GuardedArbiter g = guarded();
        Signed<SubmitWriteUp> req = fx.submit("bob", "login-bypass", SQL_INJECTION, 1);
        ProofOfWork tooEasy = ProofOfWork.mint(req.payload().canonicalBytes(), MIN - 4);
        AdmissionException e = assertThrows(AdmissionException.class, () -> g.submitWriteUp(req, tooEasy));
        assertEquals(AdmissionException.Reason.INSUFFICIENT_DIFFICULTY, e.reason());
    }

    @Test
    void aProofMintedForADifferentRequestIsRefused() throws Exception {
        GuardedArbiter g = guarded();
        Signed<SubmitWriteUp> req = fx.submit("bob", "login-bypass", SQL_INJECTION, 1);
        // Mint against a different submission's bytes, then try to reuse it.
        byte[] otherBytes = fx.submit("bob", "login-bypass", XSS, 1).payload().canonicalBytes();
        ProofOfWork wrong = ProofOfWork.mint(otherBytes, MIN);
        AdmissionException e = assertThrows(AdmissionException.class, () -> g.submitWriteUp(req, wrong));
        assertEquals(AdmissionException.Reason.INVALID, e.reason());
    }
}
