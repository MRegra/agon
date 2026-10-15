package dev.sobatista.agon.server;

import dev.sobatista.agon.arbiter.Arbiter;
import dev.sobatista.agon.arbiter.ArbiterException;
import dev.sobatista.agon.crypto.Signable;
import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.Scoreboard;
import dev.sobatista.agon.message.PublishChallenge;
import dev.sobatista.agon.message.Receipt;
import dev.sobatista.agon.message.ScoreQuery;
import dev.sobatista.agon.message.SubmitWriteUp;
import dev.sobatista.agon.model.Challenge;
import dev.sobatista.agon.pow.ProofOfWork;

import java.security.PublicKey;

/**
 * An admission gate in front of an {@link Arbiter}: every state-changing request must carry a Proof of Work
 * bound to that request's exact bytes and meeting a minimum difficulty, checked here before the arbiter does
 * any work. Reads are free. This is the anti-flood control the original project only ran on the client.
 *
 * <p>Checking a proof is a single hash, so the gate is cheap to the server and expensive to a flooder:
 * minting a stamp costs the client roughly {@code 2^difficulty} hashes, and a stamp minted for one submission
 * cannot be reused for another because the submission's canonical bytes are hashed into it.
 */
public final class GuardedArbiter {
    /** The least work the server will accept, in leading zero bits. Tunable; the demo uses this value. */
    public static final int MIN_DIFFICULTY = 18;

    private final Arbiter delegate;
    private final int minDifficulty;

    public GuardedArbiter(Arbiter delegate) {
        this(delegate, MIN_DIFFICULTY);
    }

    public GuardedArbiter(Arbiter delegate, int minDifficulty) {
        this.delegate = delegate;
        this.minDifficulty = minDifficulty;
    }

    public Challenge publishChallenge(Signed<PublishChallenge> request, ProofOfWork pow)
            throws ArbiterException, AdmissionException {
        requireWork(request.payload(), pow);
        return delegate.publishChallenge(request);
    }

    public Signed<Receipt> submitWriteUp(Signed<SubmitWriteUp> request, ProofOfWork pow)
            throws ArbiterException, AdmissionException {
        requireWork(request.payload(), pow);
        return delegate.submitWriteUp(request);
    }

    public Scoreboard scoreboard(Signed<ScoreQuery> request) throws ArbiterException {
        return delegate.scoreboard(request);
    }

    public PublicKey publicKey() {
        return delegate.publicKey();
    }

    /** The difficulty a client must mint at to be admitted — hand this to clients up front. */
    public int minDifficulty() {
        return minDifficulty;
    }

    private void requireWork(Signable request, ProofOfWork pow) throws AdmissionException {
        if (pow == null) {
            throw new AdmissionException(AdmissionException.Reason.MISSING);
        }
        if (pow.difficulty() < minDifficulty) {
            throw new AdmissionException(AdmissionException.Reason.INSUFFICIENT_DIFFICULTY);
        }
        if (!pow.satisfies(request.canonicalBytes())) {
            throw new AdmissionException(AdmissionException.Reason.INVALID);
        }
    }
}
