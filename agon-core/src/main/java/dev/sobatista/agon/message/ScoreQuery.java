package dev.sobatista.agon.message;

import dev.sobatista.agon.crypto.Bytes;
import dev.sobatista.agon.crypto.Signable;

/**
 * A signed request to read the scoreboard. Reads change no state, so instead of a sequence number they carry
 * a {@code nonce} the arbiter remembers per reader — a duplicate read is refused, so a captured read request
 * cannot be replayed to probe the board.
 */
public record ScoreQuery(String readerId, long nonce) implements Signable {

    @Override
    public byte[] canonicalBytes() {
        return Bytes.of("ScoreQuery", readerId, nonce);
    }
}
