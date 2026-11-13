/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: AuditLog.java
 *
 * Append-only, size-capped security audit log that records events without secrets.
 */

package securebank;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The bank's append-only security audit log.
 */
final class AuditLog {

    // CWE-778 (Insufficient Logging): every security-relevant event is recorded with when it
    // happened, what it was, whether it succeeded, who did it, and the real network address it
    // came from: sign-ins (successful and failed), lockouts, throttling, permission and ownership
    // denials, privilege elevation and its removal, password and settings changes, rejected
    // files, and large cash withdrawals. That gives investigators a trail to detect an attack,
    // see how it happened, and find where it came from.
    enum Event {
        STARTUP, BOOTSTRAP, USER_REGISTERED, STAFF_CREATED,
        LOGIN_SUCCESS, LOGIN_FAILURE, ACCOUNT_LOCKED, ACCOUNT_UNLOCKED, ADDRESS_THROTTLED,
        INSECURE_CONNECTION_REJECTED, SESSION_EXPIRED, LOGOUT,
        PASSWORD_CHANGED, PASSWORD_CHANGE_FAILED,
        PERMISSION_DENIED, OWNERSHIP_VIOLATION, PRIVILEGE_ELEVATED, PRIVILEGE_RESTORED,
        LARGE_WITHDRAWAL, CONFIG_CHANGED, CONFIG_CHANGE_REJECTED, SUSPICIOUS_INPUT,
        STATEMENT_EXPORTED, STATEMENT_ACCESS_DENIED, BATCH_IMPORTED, BATCH_REJECTED, MONTH_END_RUN
    }

    enum Outcome { SUCCESS, FAILURE, DENIED }

    record Entry(Instant time, Event event, Outcome outcome, String actor, String source, String detail) {
        String toLine() {
            // CWE-134 (Use of Externally-Controlled Format String): the format string is a constant.
            // Usernames, addresses, and details (which may include text a user typed) are only
            // ever passed as %s arguments, so a value like "%n%s" is printed literally and can't
            // change how the line is built.
            return String.format(Locale.ROOT, "%s  %-28s %-7s actor=%-10s from=%-15s %s",
                    time.truncatedTo(ChronoUnit.SECONDS), event, outcome, actor, source, detail);
        }
    }

    // CWE-779 (Logging of Excessive Data): the log records only what an investigator needs.
    //  - Only security events are logged, not every balance lookup or routine transfer (those
    //    belong in the account's transaction history).
    //  - Passwords, authenticator codes, password hashes, and session tokens are never logged,
    //    and account numbers are masked to their last four digits.
    //  - Each field is length-capped, so one huge input can't flood the log.
    //  - The file is size-capped and rotated, keeping a fixed number of old files, so the log
    //    can't fill the disk. (A real deployment would also ship entries to a central log store.)
    private static final int MAX_FIELD_CHARS = 32;
    private static final int MAX_DETAIL_CHARS = 120;
    private static final long MAX_FILE_BYTES = 512L * 1024;
    private static final int BACKUP_FILES = 3;
    private static final int RECENT_ENTRIES_KEPT = 500;

    private final Path file;
    private final Clock clock;
    // CWE-366 (listed in our report as CWE-336, Race Condition within a Thread): events arrive from
    // many threads; record() and recent() are synchronized, so entries are never interleaved,
    // lost, or read half-written.
    private final ArrayDeque<Entry> recent = new ArrayDeque<>();
    private boolean fileWarningShown;

    AuditLog(Path directory, Clock clock) throws IOException {
        this.file = directory.resolve("audit.log");
        this.clock = clock;
        if (!Files.exists(file)) {
            SecureFiles.createOwnerOnlyFile(file);
        }
    }

    Path file() {
        return file;
    }

    synchronized void record(Event event, Outcome outcome, String actor, String source, String detail) {
        Entry entry = new Entry(clock.instant(), event, outcome,
                clean(actor, MAX_FIELD_CHARS), clean(source, MAX_FIELD_CHARS), clean(detail, MAX_DETAIL_CHARS));
        recent.addLast(entry);
        if (recent.size() > RECENT_ENTRIES_KEPT) {
            recent.removeFirst();
        }
        append(entry.toLine());
    }

    synchronized List<Entry> recent(int max) {
        List<Entry> all = new ArrayList<>(recent);
        int count = Math.min(Math.max(max, 0), all.size());
        // CWE-375: an unmodifiable copy, so a reader can't edit or delete log entries.
        return List.copyOf(all.subList(all.size() - count, all.size()));
    }

    static String maskAccount(String accountId) {
        if (accountId == null || accountId.length() < 4) {
            return "SB-******????";
        }
        return "SB-******" + accountId.substring(accountId.length() - 4);
    }

    private static String clean(String value, int maxChars) {
        if (value == null || value.isEmpty()) {
            return "-";
        }
        // Replace line breaks and other control characters, so nobody can forge extra log lines.
        String flattened = value.replaceAll("\\p{Cntrl}", "_");
        return flattened.length() <= maxChars ? flattened : flattened.substring(0, maxChars - 3) + "...";
    }

    private void append(String line) {
        try {
            rotateIfNeeded();
            Files.writeString(file, line + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            // CWE-431 (Missing Handler): a full disk must not crash a customer's request, but it
            // must not fail silently either. Entries stay in memory and the operator is warned once.
            if (!fileWarningShown) {
                System.err.println("WARNING: the audit log file could not be written; entries are being kept in memory.");
                fileWarningShown = true;
            }
        }
    }

    private void rotateIfNeeded() throws IOException {
        if (!Files.exists(file) || Files.size(file) < MAX_FILE_BYTES) {
            return;
        }
        // CWE-1095: "index" is only changed by the loop header; the bounds are constants.
        for (int index = BACKUP_FILES - 1; index >= 1; index--) {
            Path older = backup(index);
            if (Files.exists(older)) {
                Files.move(older, backup(index + 1), StandardCopyOption.REPLACE_EXISTING);
            }
        }
        Files.move(file, backup(1), StandardCopyOption.REPLACE_EXISTING);
        SecureFiles.createOwnerOnlyFile(file);
    }

    private Path backup(int index) {
        return file.resolveSibling("audit.log." + index);
    }
}
