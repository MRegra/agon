package dev.sobatista.agon;

import dev.sobatista.agon.crypto.Bytes;
import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.message.SubmitWriteUp;
import dev.sobatista.agon.model.VulnerabilityClass;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignaturesTest {
    private final Fixtures fx = new Fixtures();

    @Test
    void aGenuineSignatureVerifiesAndATamperedPayloadDoesNot() {
        SubmitWriteUp body = new SubmitWriteUp("bob", "login-bypass", VulnerabilityClass.SQL_INJECTION, "poc", 1);
        Signed<SubmitWriteUp> signed = Signed.sign(body, "bob", fx.priv("bob"));

        assertTrue(signed.verify(fx.pub("bob")), "bob's own key verifies bob's signature");
        assertFalse(signed.verify(fx.pub("alice")), "a different key does not verify it");

        // Keep the signature, change one field: the signature no longer covers the bytes.
        SubmitWriteUp tampered = new SubmitWriteUp("bob", "login-bypass", VulnerabilityClass.XSS, "poc", 1);
        Signed<SubmitWriteUp> forged = new Signed<>(tampered, signed.signerId(), signed.signature());
        assertFalse(forged.verify(fx.pub("bob")), "a flipped vulnerability class breaks verification");
    }

    @Test
    void aNullSignatureFailsClosedInsteadOfThrowing() {
        SubmitWriteUp body = new SubmitWriteUp("bob", "c", VulnerabilityClass.XSS, "p", 1);
        assertFalse(new Signed<>(body, "bob", null).verify(fx.pub("bob")));
    }

    @Test
    void canonicalBytesAreUnambiguousAcrossFieldBoundaries() {
        // Without a separator, ("a","bc") and ("ab","c") would collide; with one they must not.
        assertFalse(java.util.Arrays.equals(Bytes.of("a", "bc"), Bytes.of("ab", "c")));
        assertArrayEquals(Bytes.of("a", "bc"), Bytes.of("a", "bc"));
    }
}
