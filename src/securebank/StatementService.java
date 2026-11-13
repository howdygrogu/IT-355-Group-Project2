/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: StatementService.java
 *
 * Service that writes monthly statement files securely and lets customers read only their own.
 */

package securebank;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import securebank.AuditLog.Event;
import securebank.AuditLog.Outcome;

/**
 * Writes monthly statements to files and lets customers download their own.
 */
final class StatementService {

    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);
    private static final String NOT_FOUND = "Statement not found.";

    private final AccountService accounts;
    private final AuthService auth;
    private final AuditLog audit;
    private final Clock clock;
    private final Path root;

    StatementService(AccountService accounts, AuthService auth, AuditLog audit, Clock clock, Path dataRoot)
            throws IOException {
        this.accounts = accounts;
        this.auth = auth;
        this.audit = audit;
        this.clock = clock;
        this.root = SecureFiles.createOwnerOnlyDirectory(dataRoot.resolve("statements"));
    }

    /** Creates this month's statement for one of the user's accounts and returns its file name. */
    String exportStatement(Session session, String accountId) {
        AccountService.StatementData data = accounts.statementData(session, accountId);
        YearMonth month = YearMonth.now(clock);
        String body = render(data, month);
        try {
            // Each customer's statements live in a folder named after their random internal ID,
            // never their username, so the path can't be steered by anything the user types.
            Path userDirectory = SecureFiles.createOwnerOnlyDirectory(root.resolve(session.userId()));
            // CWE-378 (Creation of Temporary File With Insecure Permissions): the statement is
            // first written to a temporary file that is owner-only from the moment it exists and
            // has an unpredictable name. Only when it's complete is it renamed into place, so no
            // one can read a half-written statement or swap in a file of their own.
            Path partial = SecureFiles.createOwnerOnlyTempFile(userDirectory, "stmt-", ".partial");
            try {
                Files.writeString(partial, body, StandardCharsets.UTF_8);
                String last4 = data.summary().id().substring(data.summary().id().length() - 4);
                String name = String.format(Locale.ROOT, "stmt-%s-%04d%02d-%s.txt",
                        last4, month.getYear(), month.getMonthValue(), SecureRandomSource.base32(8));
                Files.move(partial, userDirectory.resolve(name), StandardCopyOption.ATOMIC_MOVE);
                audit.record(Event.STATEMENT_EXPORTED, Outcome.SUCCESS, session.username(), session.origin(),
                        "statement for " + AuditLog.maskAccount(accountId));
                return name;
            } finally {
                Files.deleteIfExists(partial);
            }
        } catch (IOException e) {
            // CWE-431 (Missing Handler): disk problems become a clear, safe message for the
            // customer (no file paths or stack traces), and the temp file is always cleaned up.
            throw new BankException("The statement could not be created. Please try again later.");
        }
    }

    /** Reads back one of the signed-in user's own statements by file name. */
    String readStatement(Session session, String fileName) {
        auth.authorize(session, Permission.EXPORT_OWN_STATEMENT, "read statements");
        // CWE-625: the name must match the exact statement format, which has no room for "/",
        // "\", "..", or capital letters.
        if (!Validation.isValid(Validation.STATEMENT_FILE, fileName)) {
            audit.record(Event.STATEMENT_ACCESS_DENIED, Outcome.DENIED, session.username(), session.origin(),
                    "requested a file name that is not a statement name");
            throw new BankException.AccessDenied(NOT_FOUND);
        }
        try {
            Path userDirectory = root.resolve(session.userId());
            if (!Files.isDirectory(userDirectory, LinkOption.NOFOLLOW_LINKS)) {
                throw new BankException.AccessDenied(NOT_FOUND);
            }
            Path realDirectory = userDirectory.toRealPath();
            Path candidate = realDirectory.resolve(fileName);
            if (!Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS)) {
                throw new BankException.AccessDenied(NOT_FOUND);
            }
            // CWE-289 (Authentication Bypass by Alternate Name): one file can have many names:
            // "a/../b", symbolic links, different capitalization on Windows and macOS, or Windows
            // 8.3 short names such as STMT-1~1.TXT. The access check is done on the file's ONE
            // canonical name from toRealPath(), and the file must sit directly inside this
            // user's own folder. (The strict name pattern above already blocks these; this is a
            // second, independent check.)
            Path realFile = candidate.toRealPath();
            if (!realDirectory.equals(realFile.getParent())) {
                audit.record(Event.STATEMENT_ACCESS_DENIED, Outcome.DENIED, session.username(), session.origin(),
                        "statement path resolved outside the user's folder");
                throw new BankException.AccessDenied(NOT_FOUND);
            }
            return Files.readString(realFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new BankException("The statement could not be read. Please try again later.");
        }
    }

    static String render(AccountService.StatementData data, YearMonth month) {
        AccountSummary summary = data.summary();
        StringBuilder out = new StringBuilder();
        // CWE-134 (Use of Externally-Controlled Format String): every format string below is a
        // constant. Memos and nicknames are typed by customers (and payroll memos come from an
        // outside file), so they're only ever passed as %s arguments. A memo like "%n%s" is
        // printed exactly as typed and can't read other arguments, crash the formatter, or
        // change the layout.
        out.append(String.format(Locale.US, "SecureBank monthly statement for %s%n", month));
        out.append(String.format(Locale.US, "Account %s  (%s)%n", AuditLog.maskAccount(summary.id()), summary.product()));
        if (summary.nickname() != null) {
            out.append(String.format(Locale.US, "Nickname: %s%n", summary.nickname()));
        }
        out.append(String.format(Locale.US, "%-10s  %-12s  %13s  %13s  %s%n", "Date", "Type", "Amount", "Balance", "Memo"));
        // CWE-1095: a for-each over an immutable list; there is no loop variable to mis-update.
        for (Transaction t : data.history()) {
            String signedAmount = (t.type().isCredit() ? "+" : "-") + Money.format(t.amountCents());
            out.append(String.format(Locale.US, "%-10s  %-12s  %13s  %13s  %s%n",
                    DATE.format(t.time()), t.type().label(), signedAmount, Money.format(t.balanceAfterCents()), t.memo()));
        }
        out.append(String.format(Locale.US, "Closing balance: %s%n", Money.format(summary.balanceCents())));
        return out.toString();
    }
}
