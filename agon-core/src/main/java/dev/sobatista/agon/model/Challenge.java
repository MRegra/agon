package dev.sobatista.agon.model;

import java.io.Serializable;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * A challenge a group leader publishes: a named, located, vulnerable artifact that contains a known set of
 * {@link VulnerabilityClass}es for hackers to find and write up.
 *
 * @param name        a unique, human-readable name
 * @param description what the challenge is
 * @param location    where the vulnerability lives (a file, an endpoint, a function)
 * @param authorId    the leader who published it — they cannot score their own challenge
 * @param classes     the vulnerability classes this challenge actually contains (never empty)
 */
public record Challenge(String name, String description, String location, String authorId,
                        Set<VulnerabilityClass> classes) implements Serializable {

    public Challenge {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("challenge name is required");
        }
        if (classes == null || classes.isEmpty()) {
            throw new IllegalArgumentException("a challenge must declare at least one vulnerability class");
        }
        // Defensive, deterministic copy: the set is part of the challenge's identity and must not change under us.
        classes = Collections.unmodifiableSet(new TreeSet<>(classes));
    }

    public boolean contains(VulnerabilityClass vuln) {
        return classes.contains(vuln);
    }
}
