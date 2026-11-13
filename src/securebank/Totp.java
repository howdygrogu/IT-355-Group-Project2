/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: Totp.java
 *
 * Time-based one-time password (RFC 6238) generation and replay-safe code checking.
 */

package securebank;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Time-based one-time passwords (RFC 6238): the 6-digit codes shown by an authenticator app.
 */
final class Totp {

    // CWE-308 (Use of Single-factor Authentication): a password is something you know; a TOTP
    // code proves you also have something, the phone holding this secret. SecureBank requires
    // both on every sign-in and every password change, so a stolen or guessed password alone
    // is never enough. There is no setting that turns this requirement off.

    static final long STEP_SECONDS = 30;
    private static final int SECRET_BYTES = 32;
    private static final String ALGORITHM = "HmacSHA256";

    private Totp() {
    }

    static byte[] newSecret() {
        return SecureRandomSource.bytes(SECRET_BYTES);
    }

    static long stepAt(Instant time) {
        return Math.floorDiv(time.getEpochSecond(), STEP_SECONDS);
    }

    static String codeAt(byte[] secret, long step) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret, ALGORITHM));
            byte[] h = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(step).array());
            int offset = h[h.length - 1] & 0x0F;
            int binary = ((h[offset] & 0x7F) << 24)
                    | ((h[offset + 1] & 0xFF) << 16)
                    | ((h[offset + 2] & 0xFF) << 8)
                    | (h[offset + 3] & 0xFF);
            return String.format(Locale.ROOT, "%06d", binary % 1_000_000);
        } catch (GeneralSecurityException e) {
            // CWE-431: fail closed with a clear error rather than leaving the case unhandled.
            throw new IllegalStateException("One-time codes are unavailable on this Java runtime.", e);
        }
    }

    /**
     * Returns the time step that {@code code} belongs to, or -1 if it doesn't match.
     * Codes from the previous, current, and next 30-second window are accepted (to allow
     * for clock drift), but never a step at or before {@code lastUsedStep}, so a code
     * can't be replayed.
     */
    static long match(byte[] secret, String code, Instant now, long lastUsedStep) {
        if (!Validation.isValid(Validation.TOTP_CODE, code)) {
            return -1;
        }
        byte[] submitted = code.getBytes(StandardCharsets.US_ASCII);
        long current = stepAt(now);
        long matched = -1;
        // CWE-1095 (Loop Condition Value Update within the Loop): "offset" is only changed by the
        // loop header and the bounds are constants, so it always runs exactly three times. The
        // body records a match instead of breaking out early, which also keeps the timing even.
        for (long offset = -1; offset <= 1; offset++) {
            long step = current + offset;
            byte[] expected = codeAt(secret, step).getBytes(StandardCharsets.US_ASCII);
            if (MessageDigest.isEqual(expected, submitted) && step > lastUsedStep) {
                matched = step;
            }
        }
        return matched;
    }
}
