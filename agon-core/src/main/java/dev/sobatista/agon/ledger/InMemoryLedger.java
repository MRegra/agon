package dev.sobatista.agon.ledger;

import dev.sobatista.agon.crypto.Signed;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** A ledger that lives only in memory — for tests and the in-process demo. */
public final class InMemoryLedger implements Ledger {
    private final List<Signed<ScoreEntry>> entries = new ArrayList<>();

    @Override
    public void append(Signed<ScoreEntry> entry) {
        Ledger.checkLink(this, entry);
        entries.add(entry);
    }

    @Override
    public List<Signed<ScoreEntry>> entries() {
        return Collections.unmodifiableList(entries);
    }

    @Override
    public long size() {
        return entries.size();
    }
}
