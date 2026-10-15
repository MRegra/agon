package dev.sobatista.agon.server;

import dev.sobatista.agon.crypto.Signatures;
import dev.sobatista.agon.model.KeyDirectory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicKeyStoreTest {

    @Test
    void storeThenLoadRoundTripsThePublicKey(@TempDir Path dir) {
        PublicKeyStore store = new PublicKeyStore(dir);
        KeyPair alice = Signatures.generateRsa(1024);

        store.store("alice", alice.getPublic());
        assertEquals(alice.getPublic(), store.load("alice"));
    }

    @Test
    void itBuildsADirectoryForTheStoredUsers(@TempDir Path dir) {
        PublicKeyStore store = new PublicKeyStore(dir);
        KeyPair alice = Signatures.generateRsa(1024);
        KeyPair bob = Signatures.generateRsa(1024);
        store.store("alice", alice.getPublic());
        store.store("bob", bob.getPublic());

        KeyDirectory directory = store.directoryFor(java.util.List.of("alice", "bob"));
        assertTrue(directory.knows("alice"));
        assertEquals(bob.getPublic(), directory.keyOf("bob"));
        assertFalse(directory.knows("carol"));
    }
}
