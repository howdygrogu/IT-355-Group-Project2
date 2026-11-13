/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: Session.java
 *
 * Immutable signed-in session with its user, role, origin address, and expiry time.
 */

package securebank;

import java.time.Instant;

/**
 * A signed-in user. Sessions are immutable: nothing about a session can change after sign-in,
 * so it's safe to use one from several threads at once.
 */
final class Session {

    private final String token;
    private final String userId;
    private final String username;
    private final Role role;
    private final String origin;
    private final Instant expiresAt;
    private final boolean passwordChangeRequired;

    Session(String token, String userId, String username, Role role, String origin,
            Instant expiresAt, boolean passwordChangeRequired) {
        this.token = token;
        this.userId = userId;
        this.username = username;
        this.role = role;
        this.origin = origin;
        this.expiresAt = expiresAt;
        this.passwordChangeRequired = passwordChangeRequired;
    }

    /** The bearer token. Package-private, and never logged or printed. */
    String token() {
        return token;
    }

    String userId() {
        return userId;
    }

    String username() {
        return username;
    }

    Role role() {
        return role;
    }

    /** The network address the user signed in from (taken from the connection, not a header). */
    String origin() {
        return origin;
    }

    Instant expiresAt() {
        return expiresAt;
    }

    boolean passwordChangeRequired() {
        return passwordChangeRequired;
    }

    @Override
    public String toString() {
        // CWE-779: leave the token out, so a session that ends up in a log doesn't leak it.
        return "Session[" + username + ", " + role + ", expires " + expiresAt + "]";
    }
}
