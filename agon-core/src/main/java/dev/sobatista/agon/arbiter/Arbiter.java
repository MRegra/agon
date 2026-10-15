package dev.sobatista.agon.arbiter;

import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.Scoreboard;
import dev.sobatista.agon.message.PublishChallenge;
import dev.sobatista.agon.message.Receipt;
import dev.sobatista.agon.message.ScoreQuery;
import dev.sobatista.agon.message.SubmitWriteUp;
import dev.sobatista.agon.model.Challenge;

import java.security.PublicKey;

/**
 * The scoring authority. Every request is a {@link Signed} envelope; every result that matters is signed back,
 * so a hacker holds non-repudiable proof of their award and anyone can audit the scoreboard without trusting
 * the arbiter's word. An arbiter that refuses a request says exactly why ({@link ArbiterException}).
 */
public interface Arbiter {

    /** A leader publishes a challenge for their group. */
    Challenge publishChallenge(Signed<PublishChallenge> request) throws ArbiterException;

    /** A hacker submits a write-up; on acceptance it is recorded in the ledger and a signed receipt returned. */
    Signed<Receipt> submitWriteUp(Signed<SubmitWriteUp> request) throws ArbiterException;

    /** An authenticated read of the scoreboard. The returned view can be verified against {@link #publicKey()}. */
    Scoreboard scoreboard(Signed<ScoreQuery> request) throws ArbiterException;

    /** The arbiter's public key — verifies receipts and every ledger entry. */
    PublicKey publicKey();
}
