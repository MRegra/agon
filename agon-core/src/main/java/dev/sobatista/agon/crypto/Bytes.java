package dev.sobatista.agon.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Builds canonical, unambiguous byte encodings for signing and hashing.
 *
 * <p>Fields are joined with a unit-separator (0x1F) so that {@code of("a","bc")} and {@code of("ab","c")}
 * never produce the same bytes — a real signing pitfall. Whatever a message decides to sign, it signs
 * <em>exactly</em> those bytes, so the signature covers every field that matters (the acting user, the
 * challenge, the vulnerability class <em>and</em> the sequence number), not an opaque blob.
 *
 * <p>The original project signed a fixed-length substring of the request string; a field that fell outside
 * that window was never covered. Here the message, not an offset, decides what is signed.
 */
public final class Bytes {
    private static final int SEP = 0x1F;

    private Bytes() {}

    public static byte[] of(Object... fields) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Object f : fields) {
            byte[] b = String.valueOf(f).getBytes(StandardCharsets.UTF_8);
            out.write(b, 0, b.length);
            out.write(SEP);
        }
        return out.toByteArray();
    }
}
