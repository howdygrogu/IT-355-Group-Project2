/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: User.java
 *
 * A person who can sign in, with their password hash, authenticator secret, and lockout state.
 */

package securebank;

import java.time.Instant;
import java.util.Base64;

/**
 * One person who can sign in to SecureBank, and their sign-in state.
 */
final class User {

    enum CredentialCheck { OK, FAILED, NOW_LOCKED, LOCKED }

    private final String id;
    private final String username;
    private final String displayName;
    private final Role role;
    private final byte[] totpSecret;

    // CWE-366 (Race Condition within a Thread): two sign-in
    // attempts for the same user can arrive on different threads at the same moment. All of the
    // mutable fields below are only read or changed inside methods synchronized on this User, so
    // the failure counter can't lose updates and two threads can't both accept the same code.
    private PasswordHasher.StoredPassword password;
    private long lastUsedTotpStep = -1;
    private int failedAttempts;
    private boolean locked;
    private boolean passwordChangeRequired;

    User(String id, String username, String displayName, Role role,
         PasswordHasher.StoredPassword password, byte[] totpSecret, boolean passwordChangeRequired) {
        this.id = id;
        this.username = username;
        this.displayName = displayName;
        this.role = role;
        this.password = password;
        this.totpSecret = totpSecret.clone();
        this.passwordChangeRequired = passwordChangeRequired;
    }

    String id() {
        return id;
    }

    String username() {
        return username;
    }

    String displayName() {
        return displayName;
    }

    Role role() {
        return role;
    }

    /**
     * Checks a password AND an authenticator code together.
     */
    synchronized CredentialCheck checkCredentials(PasswordHasher hasher, char[] candidatePassword,
                                                  String totpCode, Instant now, int maxFailures) {
        if (locked) {
            hasher.verifyAgainstDummy(candidatePassword);
            return CredentialCheck.LOCKED;
        }
        boolean passwordOk = hasher.verify(candidatePassword, password);
        // CWE-308: the password alone is never enough; the code from the user's phone must match too.
        long step = Totp.match(totpSecret, totpCode, now, lastUsedTotpStep);
        if (passwordOk && step >= 0) {
            failedAttempts = 0;
            lastUsedTotpStep = step;
            return CredentialCheck.OK;
        }
        failedAttempts++;
        if (failedAttempts >= maxFailures) {
            locked = true;
            return CredentialCheck.NOW_LOCKED;
        }
        return CredentialCheck.FAILED;
    }

    synchronized void replacePassword(PasswordHasher.StoredPassword newPassword) {
        password = newPassword;
        passwordChangeRequired = false;
    }

    synchronized boolean passwordChangeRequired() {
        return passwordChangeRequired;
    }

    synchronized boolean isLocked() {
        return locked;
    }

    synchronized void unlock() {
        locked = false;
        failedAttempts = 0;
    }

    /**
     * Returns the stored hash, Base64-encoded. Used ONLY by the demo's simulated data-breach drill
     * to show that a stolen hash can't be used to sign in (CWE-836). It never returns a password,
     * because no password is stored.
     */
    synchronized String storedHashForBreachDrill() {
        return Base64.getEncoder().encodeToString(password.hash());
    }

    @Override
    public String toString() {
        return "User[" + username + ", " + role + "]";
    }
}
