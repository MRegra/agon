package dev.sobatista.agon.server;

import dev.sobatista.agon.crypto.Signed;
import dev.sobatista.agon.ledger.Ledger;
import dev.sobatista.agon.ledger.ScoreEntry;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * A durable, append-only ledger backed by a single file — the scoreboard's write-ahead log.
 *
 * <p>Each entry is one newline-terminated, Base64-encoded, serialized {@code Signed<ScoreEntry>}. An append
 * writes the whole line and <strong>fsyncs it before returning</strong>, so a confirmed award is on disk; an
 * award lost to a crash before the fsync simply never happened. On open the ledger replays every <em>complete</em>
 * line and stops at a torn final line — the fingerprint of a crash mid-write — rather than choking on it. The
 * append-time link check means a file whose middle was edited will also fail to reload as a valid chain.
 */
public final class FileLedger implements Ledger {
    private final Path file;
    private final List<Signed<ScoreEntry>> entries = new ArrayList<>();

    public FileLedger(Path file) {
        this.file = file;
        replay();
    }

    private void replay() {
        if (!Files.exists(file)) {
            return;
        }
        byte[] raw;
        try {
            raw = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read ledger " + file, e);
        }
        // Keep only complete, newline-terminated lines; a trailing partial line is a torn tail and is dropped.
        int lastNewline = lastIndexOf(raw, (byte) '\n');
        for (String line : new String(raw, 0, lastNewline + 1, StandardCharsets.UTF_8).split("\n")) {
            if (line.isEmpty()) {
                continue;
            }
            Signed<ScoreEntry> entry = decode(line);
            Ledger.checkLink(this, entry);   // a tampered/reordered file fails here on reload
            entries.add(entry);
        }
    }

    @Override
    public void append(Signed<ScoreEntry> entry) {
        Ledger.checkLink(this, entry);
        String line = encode(entry) + "\n";
        try (var ch = java.nio.channels.FileChannel.open(file,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            ch.write(StandardCharsets.UTF_8.encode(line));
            ch.force(true);   // the award is not confirmed until it is durable
        } catch (IOException e) {
            throw new UncheckedIOException("cannot append to ledger " + file, e);
        }
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

    private static String encode(Signed<ScoreEntry> entry) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(entry);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return Base64.getEncoder().encodeToString(bytes.toByteArray());
    }

    @SuppressWarnings("unchecked")
    private static Signed<ScoreEntry> decode(String line) {
        byte[] bytes = Base64.getDecoder().decode(line);
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            return (Signed<ScoreEntry>) in.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new UncheckedIOException(new IOException("corrupt ledger line", e));
        }
    }

    private static int lastIndexOf(byte[] data, byte target) {
        for (int i = data.length - 1; i >= 0; i--) {
            if (data[i] == target) {
                return i;
            }
        }
        return -1;
    }
}
