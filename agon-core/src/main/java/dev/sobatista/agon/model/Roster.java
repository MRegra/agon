package dev.sobatista.agon.model;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The fixed, globally-known membership of a competition: who the hackers are, which group each belongs to,
 * and which of them lead a group. The original kept this in a database the server trusted; here it is an
 * explicit, immutable value so the rules can be read and tested in one place.
 *
 * <p>A <strong>leader</strong> is the only member who may publish challenges for their group. Scores a hacker
 * earns accrue to the hacker's group.
 */
public final class Roster implements Serializable {
    private final Map<String, String> groupOf;   // hacker -> group
    private final Set<String> leaders;

    private Roster(Map<String, String> groupOf, Set<String> leaders) {
        this.groupOf = Collections.unmodifiableMap(new HashMap<>(groupOf));
        this.leaders = Collections.unmodifiableSet(new HashSet<>(leaders));
    }

    public boolean knows(String userId) {
        return groupOf.containsKey(userId);
    }

    public boolean isLeader(String userId) {
        return leaders.contains(userId);
    }

    /** The group a user belongs to, or {@code null} if the user is unknown. */
    public String groupOf(String userId) {
        return groupOf.get(userId);
    }

    public Set<String> users() {
        return groupOf.keySet();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final Map<String, String> groupOf = new HashMap<>();
        private final Set<String> leaders = new HashSet<>();

        /** Add a hacker to a group. The first member registered as a leader leads the group. */
        public Builder member(String userId, String group, boolean leader) {
            groupOf.put(userId, group);
            if (leader) {
                leaders.add(userId);
            }
            return this;
        }

        public Builder member(String userId, String group) {
            return member(userId, group, false);
        }

        public Roster build() {
            return new Roster(groupOf, leaders);
        }
    }
}
