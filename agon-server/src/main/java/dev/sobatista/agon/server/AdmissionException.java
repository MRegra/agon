package dev.sobatista.agon.server;

/** Raised by the {@link GuardedArbiter} when a state-changing request lacks an acceptable Proof of Work. */
public class AdmissionException extends Exception {

    public enum Reason {
        /** No proof of work was supplied. */
        MISSING,
        /** The proof's difficulty is below the minimum the server demands. */
        INSUFFICIENT_DIFFICULTY,
        /** The proof does not hash to the required number of zero bits for this request's bytes. */
        INVALID
    }

    private final Reason reason;

    public AdmissionException(Reason reason) {
        super(reason.name());
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
