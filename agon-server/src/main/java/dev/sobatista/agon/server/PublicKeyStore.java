package dev.sobatista.agon.server;

import dev.sobatista.agon.model.KeyDirectory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;

/**
 * The PKI's job: a directory of user public keys on disk, one {@code <id>.pub} file per user (Base64 X.509).
 * The original project ran a separate PKI service the server queried for keys; the trust model is the same —
 * a signer id is only trustworthy because a key is published for it here — but it is reduced to its essence so
 * the security story stays about signatures, not a second network service.
 */
public final class PublicKeyStore {
    private final Path dir;

    public PublicKeyStore(Path dir) {
        this.dir = dir;
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot create key store " + dir, e);
        }
    }

    public void store(String userId, PublicKey key) {
        try {
            Files.writeString(dir.resolve(userId + ".pub"), Base64.getEncoder().encodeToString(key.getEncoded()));
        } catch (IOException e) {
            throw new UncheckedIOException("cannot store key for " + userId, e);
        }
    }

    public PublicKey load(String userId) {
        try {
            byte[] encoded = Base64.getDecoder().decode(Files.readString(dir.resolve(userId + ".pub")));
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("cannot load key for " + userId, e);
        }
    }

    /** Build an immutable {@link KeyDirectory} for the given user ids from the stored keys. */
    public KeyDirectory directoryFor(Collection<String> userIds) {
        KeyDirectory.Builder builder = KeyDirectory.builder();
        for (String id : userIds) {
            builder.add(id, load(id));
        }
        return builder.build();
    }
}
