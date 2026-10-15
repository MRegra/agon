package dev.sobatista.agon.arbiter;

/** Why the arbiter refused a request. Every refusal names exactly one reason, so tests can assert on it. */
public class ArbiterException extends Exception {

    public enum Reason {
        /** The acting user is not in the directory / roster. */
        UNKNOWN_USER,
        /** The signature does not verify, or the envelope is signed by someone other than the acting user. */
        BAD_SIGNATURE,
        /** The sequence number is not strictly newer than the last accepted from this user (replay/duplicate). */
        STALE_SEQUENCE,
        /** A read reused a nonce this reader already used. */
        DUPLICATE_READ,
        /** A non-leader tried to publish a challenge. */
        NOT_A_LEADER,
        /** The challenge's declared author is not the publishing leader. */
        AUTHOR_MISMATCH,
        /** A challenge with this name already exists. */
        CHALLENGE_EXISTS,
        /** The write-up references a challenge that does not exist. */
        UNKNOWN_CHALLENGE,
        /** The write-up claims a vulnerability class the challenge does not contain. */
        VULN_NOT_IN_CHALLENGE,
        /** A leader tried to score their own challenge. */
        SELF_SCORING,
        /** This hacker already has an award for this class of this challenge. */
        ALREADY_SOLVED
    }

    private final Reason reason;

    public ArbiterException(Reason reason) {
        super(reason.name());
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
