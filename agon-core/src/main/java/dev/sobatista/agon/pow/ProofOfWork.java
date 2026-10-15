package dev.sobatista.agon.pow;

import dev.sobatista.agon.crypto.Hashes;

import java.io.Serializable;
import java.nio.ByteBuffer;

/**
 * A hashcash Proof-of-Work stamp, bound to the exact bytes of a request.
 *
 * <p>Minting costs the client roughly {@code 2^difficulty} hashes: it searches for a {@code nonce} such that
 * {@code SHA-256(requestBytes || nonce)} has at least {@code difficulty} leading zero bits. Checking is a
 * single hash — and the <em>server</em> does it, against the request's own canonical bytes, before doing any
 * work. The original project ran its proof of work client-side only; here it is a server-validated admission
 * cost that makes flooding state-changing operations expensive.
 */
public record ProofOfWork(long nonce, int difficulty) implements Serializable {

    /** Mint a stamp for {@code request} at the given difficulty. Bounded only by the difficulty you choose. */
    public static ProofOfWork mint(byte[] request, int difficulty) {
        for (long nonce = 0; nonce < Long.MAX_VALUE; nonce++) {
            if (meets(request, nonce, difficulty)) {
                return new ProofOfWork(nonce, difficulty);
            }
        }
        throw new IllegalStateException("exhausted the nonce space without a solution"); // not reachable in practice
    }

    /** True if this stamp is a valid proof of work for {@code request}. */
    public boolean satisfies(byte[] request) {
        return meets(request, nonce, difficulty);
    }

    private static boolean meets(byte[] request, long nonce, int difficulty) {
        byte[] combined = ByteBuffer.allocate(request.length + Long.BYTES)
                .put(request).putLong(nonce).array();
        return Hashes.leadingZeroBits(Hashes.sha256(combined)) >= difficulty;
    }
}
