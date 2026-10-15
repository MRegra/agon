package dev.sobatista.agon.ledger;

/** Raised when a ledger is appended to inconsistently, or when a stored ledger fails verification. */
public class LedgerException extends RuntimeException {

    public enum Reason {
        /** The entry's index is not the next position in the ledger. */
        WRONG_INDEX,
        /** The entry's prevHash does not match the current head — the chain is broken. */
        BROKEN_CHAIN,
        /** The entry's signature does not verify against the arbiter's public key. */
        BAD_SIGNATURE
    }

    private final Reason reason;
    private final long index;

    public LedgerException(Reason reason, long index, String message) {
        super(message + " (entry " + index + ")");
        this.reason = reason;
        this.index = index;
    }

    public Reason reason() {
        return reason;
    }

    /** The index of the entry that broke. */
    public long index() {
        return index;
    }
}
