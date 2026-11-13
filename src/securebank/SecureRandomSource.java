/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: SecureRandomSource.java
 *
 * Single shared SecureRandom used for tokens, salts, IDs, secrets, and passphrases.
 */

package securebank;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * The single source of randomness for everything security-related in SecureBank:
 * salts, authenticator secrets, session tokens, account numbers, and transaction IDs.
 */
final class SecureRandomSource {

    // CWE-331 (Insufficient Entropy): every random value in the bank comes from SecureRandom, a
    // cryptographically strong generator. We never use java.util.Random or Math.random(), whose
    // output can be predicted after seeing a few values, so session tokens, salts, and account
    // numbers can't be guessed.
    //
    // CWE-336 (Same Seed in Pseudo-Random Number Generator): the generator is built with the
    // no-argument constructor, so the JDK seeds it from the operating system's entropy source.
    // We never call setSeed() or pass in a fixed or time-based seed, so no two runs (and no two
    // servers) ever produce the same sequence of "random" values.
    //
    // SecureRandom is thread-safe, so one shared instance can be used by many threads at once
    // (see CWE-366 / the report's CWE-336 entry, Race Condition within a Thread).
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final char[] BASE32 = "abcdefghijklmnopqrstuvwxyz234567".toCharArray();
    private static final char[] PASSPHRASE_CHARS =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!@#".toCharArray();

    private SecureRandomSource() {
    }

    static byte[] bytes(int count) {
        byte[] out = new byte[count];
        RANDOM.nextBytes(out);
        return out;
    }

    /** 256-bit URL-safe token, used for session IDs. */
    static String token() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(32));
    }

    static String digits(int count) {
        StringBuilder out = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            out.append((char) ('0' + RANDOM.nextInt(10)));
        }
        return out.toString();
    }

    static String base32(int count) {
        StringBuilder out = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            out.append(BASE32[RANDOM.nextInt(BASE32.length)]);
        }
        return out.toString();
    }

    /**
     * A random 20-character passphrase. Used for the administrator's one-time bootstrap password
     * and by the demo's simulated people when they choose their own passwords, so no password
     * ever appears in the source code.
     */
    static char[] passphrase() {
        char[] out = new char[20];
        for (int i = 0; i < out.length; i++) {
            out[i] = PASSPHRASE_CHARS[RANDOM.nextInt(PASSPHRASE_CHARS.length)];
        }
        return out;
    }
}
