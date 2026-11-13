/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: PasswordHasher.java
 *
 * Salted, peppered PBKDF2 password hashing and constant-time password verification.
 */

package securebank;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Turns passwords into salted, slow, one-way hashes and checks passwords against them.
 */
final class PasswordHasher {

    // CWE-256 (Plaintext Storage of a Password): SecureBank never stores a password. The only
    // thing kept for each user is a StoredPassword: a random salt, an iteration count, and a hash.
    //
    // CWE-257 (Storing Passwords in a Recoverable Format): the hash is one-way. There is no
    // decryption key and no decrypt() method anywhere, so nobody, including the bank, can turn a
    // stored hash back into the password.
    //
    // CWE-261 (Weak Encoding for Password): instead of an encoding such as Base64 or a simple
    // XOR, passwords go through PBKDF2-HMAC-SHA256 with a 128-bit random salt per user and
    // 600,000 iterations (the current OWASP recommendation), producing a 256-bit result. The
    // result is then keyed with HMAC-SHA256 and a server-side pepper, so a stolen copy of the
    // user table can't even be attacked offline without the pepper.

    /** What is stored for each user instead of their password. */
    record StoredPassword(byte[] salt, int iterations, byte[] hash) {
        StoredPassword {
            // CWE-375: arrays are mutable, so the record keeps private copies...
            salt = salt.clone();
            hash = hash.clone();
        }

        // ...and only ever hands out copies.
        @Override
        public byte[] salt() {
            return salt.clone();
        }

        @Override
        public byte[] hash() {
            return hash.clone();
        }

        @Override
        public String toString() {
            // CWE-779: never print hash material if this object ends up in a log message.
            return "StoredPassword[PBKDF2-HMAC-SHA256, iterations=" + iterations + "]";
        }
    }

    static final int ITERATIONS = 600_000;
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final int MAX_CANDIDATE_CHARS = 1_024;

    private final byte[] pepper;
    private final StoredPassword dummy;

    PasswordHasher(byte[] pepper) {
        if (pepper == null || pepper.length < 32) {
            throw new IllegalArgumentException("The pepper must be at least 32 bytes.");
        }
        this.pepper = pepper.clone();
        // Used to spend the same time on sign-ins for unknown or locked users, so response times
        // don't reveal which usernames exist.
        this.dummy = hash(SecureRandomSource.passphrase());
    }

    StoredPassword hash(char[] password) {
        byte[] salt = SecureRandomSource.bytes(SALT_BYTES);
        return new StoredPassword(salt, ITERATIONS, derive(password, salt, ITERATIONS));
    }

    /**
     * Checks a password that a client just sent against what is stored.
     */
    boolean verify(char[] candidate, StoredPassword stored) {
        // CWE-836 (Use of Password Hash Instead of Password for Authentication): the client always
        // sends the actual password (over TLS) and the SERVER hashes it here, every time. A client
        // can never submit a hash as proof of identity, so a leaked StoredPassword is useless for
        // signing in: whatever is submitted, a hash included, is hashed again before comparing.
        if (candidate == null || candidate.length == 0 || candidate.length > MAX_CANDIDATE_CHARS) {
            derive(SecureRandomSource.passphrase(), stored.salt(), stored.iterations());
            return false;
        }
        byte[] actual = derive(candidate, stored.salt(), stored.iterations());
        // Constant-time comparison: how long this takes doesn't depend on how many bytes match.
        return MessageDigest.isEqual(actual, stored.hash());
    }

    /** Spends the same effort as a real check, then fails. */
    boolean verifyAgainstDummy(char[] candidate) {
        verify(candidate, dummy);
        return false;
    }

    private byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
        byte[] slowHash = null;
        try {
            slowHash = SecretKeyFactory.getInstance(KDF_ALGORITHM).generateSecret(spec).getEncoded();
            Mac mac = Mac.getInstance(MAC_ALGORITHM);
            mac.init(new SecretKeySpec(pepper, MAC_ALGORITHM));
            return mac.doFinal(slowHash);
        } catch (GeneralSecurityException e) {
            // CWE-431 (Missing Handler): if the JVM lacks the algorithm, stop with a clear error
            // instead of letting a checked exception escape or quietly skipping the check.
            throw new IllegalStateException("Password hashing is unavailable on this Java runtime.", e);
        } finally {
            spec.clearPassword();
            if (slowHash != null) {
                Arrays.fill(slowHash, (byte) 0);
            }
        }
    }
}
