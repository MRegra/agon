package dev.sobatista.agon.model;

import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Maps a user id to the public key everyone verifies that user's signatures against — the job the original
 * project gave its PKI. The set of users is fixed and known; the directory is built once and read many times.
 *
 * <p>Holding a key here is what makes a signer id trustworthy: the arbiter accepts a request only if its
 * signature verifies against the directory's key for the id the payload claims (see impersonation rules).
 */
public final class KeyDirectory {
    private final Map<String, PublicKey> keys;

    private KeyDirectory(Map<String, PublicKey> keys) {
        this.keys = Collections.unmodifiableMap(new HashMap<>(keys));
    }

    public boolean knows(String userId) {
        return keys.containsKey(userId);
    }

    /** The public key for a user, or {@code null} if the user is unknown. */
    public PublicKey keyOf(String userId) {
        return keys.get(userId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final Map<String, PublicKey> keys = new HashMap<>();

        public Builder add(String userId, PublicKey key) {
            keys.put(userId, key);
            return this;
        }

        public KeyDirectory build() {
            return new KeyDirectory(keys);
        }
    }
}
