/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: KeyVault.java
 *
 * Startup-only holder for the password pepper, loaded from the environment and sealed after use.
 */

package securebank;

import java.util.Arrays;
import java.util.Base64;

/**
 * Holds the bank's one server-side secret (the password "pepper") during startup only.
 */
final class KeyVault {

    static final String PEPPER_ENVIRONMENT_VARIABLE = "SECUREBANK_PEPPER";
    private static final int MIN_PEPPER_BYTES = 32;

    private byte[] pepper;     // guarded by "this"
    private boolean sealed;    // guarded by "this"
    private final boolean ephemeral;

    private KeyVault(byte[] pepper, boolean ephemeral) {
        this.pepper = pepper;
        this.ephemeral = ephemeral;
    }

    /**
     * Loads the pepper from the environment.
     */
    static KeyVault fromEnvironment() {
        // CWE-798 (Use of Hard-Coded Credentials): the secret is never written in the source code,
        // where anyone with a copy of the program could read it and where it would be identical
        // in every installation. It comes from the deployment environment (in production, a
        // secrets manager would inject it). If none is configured, as in this classroom demo, a
        // fresh random pepper is generated for this run only.
        //
        // CWE-260 (Password in Configuration File): the secret is deliberately NOT read from
        // securebank.properties. BankConfig refuses to start if that file contains anything that
        // looks like a password, key, or token.
        String encoded = System.getenv(PEPPER_ENVIRONMENT_VARIABLE);
        if (encoded == null || encoded.isBlank()) {
            return new KeyVault(SecureRandomSource.bytes(MIN_PEPPER_BYTES), true);
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(encoded.strip());
        } catch (IllegalArgumentException notBase64) {
            throw new IllegalStateException(PEPPER_ENVIRONMENT_VARIABLE + " must be Base64-encoded.");
        }
        if (decoded.length < MIN_PEPPER_BYTES) {
            throw new IllegalStateException(PEPPER_ENVIRONMENT_VARIABLE + " must decode to at least 32 bytes.");
        }
        return new KeyVault(decoded, false);
    }

    boolean isEphemeral() {
        return ephemeral;
    }

    synchronized byte[] pepper() {
        if (sealed) {
            throw new IllegalStateException("The key vault is sealed; secrets can only be read during startup.");
        }
        // CWE-375: hand out a copy so nobody can change the vault's contents.
        return pepper.clone();
    }

    /**
     * Called once startup is finished.
     */
    synchronized void seal() {
        // CWE-272 (Least Privilege Violation): reading raw secrets is only needed while the bank
        // starts up and hands the pepper to the PasswordHasher. After that, the running bank
        // gives up that ability for good: the bytes are wiped and every later read is refused, so
        // a bug or attacker in the running system can't pull the secret back out of the vault.
        Arrays.fill(pepper, (byte) 0);
        pepper = null;
        sealed = true;
    }
}
