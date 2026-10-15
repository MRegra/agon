package dev.sobatista.agon.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256 helpers. Used both to chain the ledger and to mint/verify Proof of Work. */
public final class Hashes {
    /** The genesis link: the previous-hash of the very first ledger entry. */
    public static final String GENESIS = "0".repeat(64);

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Hashes() {}

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // SHA-256 is always present
        }
    }

    public static String sha256Hex(byte[] data) {
        return hex(sha256(data));
    }

    public static String hex(byte[] b) {
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /** Number of leading zero bits in a digest — the unit Proof of Work counts. */
    public static int leadingZeroBits(byte[] digest) {
        int bits = 0;
        for (byte b : digest) {
            if (b == 0) {
                bits += 8;
            } else {
                bits += Integer.numberOfLeadingZeros(b & 0xFF) - 24;
                break;
            }
        }
        return bits;
    }
}
