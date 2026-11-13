/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: BatchImporter.java
 *
 * Importer that validates and applies plain-text payroll batch files without deserializing objects.
 */

package securebank;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import securebank.AuditLog.Event;
import securebank.AuditLog.Outcome;

/**
 * Imports payroll batches that employers send to the bank.
 *
 * <pre>
 * BATCH|ACME-PAYROLL-1114|2026-11-14
 * # comment lines and blank lines are ignored
 * CREDIT|SB-1234567890|320000|ACME payroll
 * </pre>
 * Amounts are in cents.
 */
final class BatchImporter {

    record Result(String batchId, int accepted, long totalCents, List<String> rejected) {
        Result {
            rejected = List.copyOf(rejected);
        }
    }

    // CWE-502 (Deserialization of Untrusted Data): a batch file comes from outside the bank, so it
    // is NEVER handed to ObjectInputStream. Turning untrusted bytes into Java objects can run code
    // from any class on the classpath while the objects are rebuilt. Instead the file is read as
    // plain UTF-8 text and each line is checked against a strict pattern. A file that starts with
    // the Java serialization header (0xACED) is rejected outright. As a second layer, Main installs
    // a JVM-wide filter that rejects every class, in case any library ever tries to deserialize.
    private static final int SERIALIZATION_MAGIC_1 = 0xAC;
    private static final int SERIALIZATION_MAGIC_2 = 0xED;

    private static final long MAX_FILE_BYTES = 256L * 1024;
    private static final int MAX_LINES = 2_000;
    private static final long MAX_CREDIT_CENTS = Money.dollars(50_000);

    // CWE-625: anchored patterns used with matches(); each field allows only its own characters.
    private static final Pattern HEADER =
            Pattern.compile("^BATCH\\|([A-Z0-9-]{3,24})\\|([0-9]{4}-[0-9]{2}-[0-9]{2})$");
    private static final Pattern CREDIT =
            Pattern.compile("^CREDIT\\|(SB-[0-9]{10})\\|([0-9]{1,9})\\|(" + Validation.MEMO_CHARS + "{0,40})$");

    private final AccountService accounts;
    private final AuthService auth;
    private final AuditLog audit;

    BatchImporter(AccountService accounts, AuthService auth, AuditLog audit) {
        this.accounts = accounts;
        this.auth = auth;
        this.audit = audit;
    }

    Result importPayroll(Session manager, Path file) {
        auth.authorize(manager, Permission.IMPORT_BATCH, "import payroll batches");
        byte[] raw = readLimited(file);
        if (raw.length >= 2 && (raw[0] & 0xFF) == SERIALIZATION_MAGIC_1 && (raw[1] & 0xFF) == SERIALIZATION_MAGIC_2) {
            audit.record(Event.BATCH_REJECTED, Outcome.DENIED, manager.username(), manager.origin(),
                    "file is a serialized Java object stream");
            throw new BankException.InvalidInput("Rejected: this file is a serialized Java object. "
                    + "SecureBank only accepts the plain-text batch format and never deserializes objects.");
        }
        List<String> lines = decodeStrictUtf8(raw).lines().toList();
        if (lines.isEmpty() || lines.size() > MAX_LINES) {
            throw new BankException.InvalidInput("Rejected: a batch must have between 1 and " + MAX_LINES + " lines.");
        }
        Matcher header = HEADER.matcher(lines.get(0));
        if (!header.matches()) {
            audit.record(Event.BATCH_REJECTED, Outcome.DENIED, manager.username(), manager.origin(),
                    "missing or malformed BATCH header");
            throw new BankException.InvalidInput("Rejected: the first line must be a BATCH header.");
        }

        int accepted = 0;
        long totalCents = 0;
        List<String> rejected = new ArrayList<>();
        // CWE-1095 (Loop Condition Value Update within the Loop): "index" is only changed by the
        // loop header, and "lines" is an immutable list that the body never changes, so every line
        // is visited exactly once. "continue" skips comments without touching the index.
        for (int index = 1; index < lines.size(); index++) {
            String line = lines.get(index);
            int lineNumber = index + 1;
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            // CWE-431 (Missing Handler): every way a single line can fail (bad format, unknown
            // account, amount out of range) is caught and reported for that line. One bad line
            // can't crash the import or leave it half-finished without saying so.
            try {
                Matcher credit = CREDIT.matcher(line);
                if (!credit.matches()) {
                    throw new BankException.InvalidInput("not a valid CREDIT record");
                }
                long cents = Long.parseLong(credit.group(2));
                if (cents <= 0 || cents > MAX_CREDIT_CENTS) {
                    throw new BankException.InvalidInput("amount must be between $0.01 and " + Money.format(MAX_CREDIT_CENTS));
                }
                accounts.creditFromBatch(manager, credit.group(1), cents, credit.group(3));
                accepted++;
                totalCents = Math.addExact(totalCents, cents);
            } catch (BankException lineProblem) {
                rejected.add(String.format(Locale.ROOT, "line %d rejected: %s", lineNumber, lineProblem.getMessage()));
            }
        }
        audit.record(Event.BATCH_IMPORTED, Outcome.SUCCESS, manager.username(), manager.origin(),
                "batch " + header.group(1) + ": " + accepted + " credited, " + rejected.size() + " rejected");
        return new Result(header.group(1), accepted, totalCents, rejected);
    }

    private static byte[] readLimited(Path file) {
        try {
            if (Files.size(file) > MAX_FILE_BYTES) {
                throw new BankException.InvalidInput("Rejected: batch files may be at most 256 KB.");
            }
            return Files.readAllBytes(file);
        } catch (IOException e) {
            throw new BankException("The batch file could not be read.");
        }
    }

    private static String decodeStrictUtf8(byte[] raw) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw))
                    .toString();
        } catch (CharacterCodingException notText) {
            throw new BankException.InvalidInput("Rejected: the batch file is not valid UTF-8 text.");
        }
    }
}
