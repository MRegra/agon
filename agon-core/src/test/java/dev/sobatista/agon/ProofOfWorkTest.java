package dev.sobatista.agon;

import dev.sobatista.agon.crypto.Bytes;
import dev.sobatista.agon.pow.ProofOfWork;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProofOfWorkTest {
    private static final int DIFFICULTY = 12;   // ~4k hashes to mint: fast, still a real search

    private final byte[] request = Bytes.of("SubmitWriteUp", "bob", "login-bypass", "SQL_INJECTION", 1);

    @Test
    void aMintedStampSatisfiesItsOwnRequest() {
        ProofOfWork pow = ProofOfWork.mint(request, DIFFICULTY);
        assertTrue(pow.satisfies(request));
        assertTrue(pow.difficulty() >= DIFFICULTY);
    }

    @Test
    void aStampIsBoundToItsRequestBytes() {
        ProofOfWork pow = ProofOfWork.mint(request, DIFFICULTY);
        byte[] otherRequest = Bytes.of("SubmitWriteUp", "bob", "login-bypass", "XSS", 1);
        assertFalse(pow.satisfies(otherRequest), "a stamp minted for one submission cannot be reused for another");
    }

    @Test
    void aWeakStampDoesNotSatisfyAHarderRequirement() {
        // A nonce found for difficulty 1 almost never clears difficulty 24.
        ProofOfWork weak = new ProofOfWork(0, 24);
        assertFalse(weak.satisfies(request));
    }
}
