/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: Validation.java
 *
 * Anchored input patterns and username canonicalization used to validate everything users type.
 */

package securebank;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Every input format SecureBank accepts, kept in one place so they're easy to review.
 */
final class Validation {

    // CWE-625 (Permissive Regular Expression): every pattern is anchored with ^ and $ and is only
    // ever used with Matcher.matches(), which requires the WHOLE input to match. With find(), or
    // without the anchors, "alice<script>" would be accepted because the substring "alice"
    // matches. matches() also rejects a trailing line break, which a bare $ would otherwise allow.
    // Each character class lists exactly what IS allowed instead of trying to list what isn't.
    static final Pattern USERNAME = Pattern.compile("^[a-z][a-z0-9_]{2,19}$");
    static final Pattern DISPLAY_NAME = Pattern.compile("^\\p{L}[\\p{L} .'-]{0,39}$");
    static final Pattern NICKNAME = Pattern.compile("^[\\p{L}\\p{N}][\\p{L}\\p{N} '-]{0,23}$");
    static final String MEMO_CHARS = "[\\p{L}\\p{N} .,'#%&()/-]";
    static final Pattern MEMO = Pattern.compile("^" + MEMO_CHARS + "{0,40}$");
    static final Pattern ACCOUNT_ID = Pattern.compile("^SB-[0-9]{10}$");
    static final Pattern STATEMENT_FILE = Pattern.compile("^stmt-[0-9]{4}-[0-9]{6}-[a-z2-7]{8}\\.txt$");
    static final Pattern TOTP_CODE = Pattern.compile("^[0-9]{6}$");

    private static final int MAX_RAW_USERNAME_CHARS = 64;

    private Validation() {
    }

    static String require(Pattern pattern, String value, String fieldName) {
        if (value == null || !pattern.matcher(value).matches()) {
            throw new BankException.InvalidInput(fieldName + " is not in an accepted format.");
        }
        return value;
    }

    static boolean isValid(Pattern pattern, String value) {
        return value != null && pattern.matcher(value).matches();
    }

    /**
     * Turns whatever the user typed into the one canonical form of a username.
     */
    static String canonicalUsername(String raw) {
        if (raw == null || raw.length() > MAX_RAW_USERNAME_CHARS) {
            throw new BankException.InvalidInput("Username is not in an accepted format.");
        }
        // CWE-289 (Authentication Bypass by Alternate Name): "alice", "ALICE", " Alice ", and the
        // full-width look-alike "ａｌｉｃｅ" must all mean the same user. NFKC normalization folds
        // Unicode look-alikes, strip() removes padding, and toLowerCase(Locale.ROOT) folds case
        // the same way on every machine. Lockout counters, duplicate checks, and permission
        // lookups all use this canonical name, so an attacker can't dodge them by respelling it.
        String canonical = Normalizer.normalize(raw, Normalizer.Form.NFKC)
                .strip()
                .toLowerCase(Locale.ROOT);
        return require(USERNAME, canonical, "Username");
    }
}
