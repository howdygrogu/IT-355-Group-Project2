/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: AuthService.java
 *
 * Service for registration, sign-in with two-factor codes, password changes, sessions, and permission checks.
 */

package securebank;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import securebank.AuditLog.Event;
import securebank.AuditLog.Outcome;
import securebank.BankConfig.Setting;

/**
 * Registration, sign-in, password changes, sessions, and permission checks.
 */
final class AuthService {

    /** What a new user takes away from enrollment: their username and their authenticator secret. */
    record Enrollment(String userId, String username, Role role, byte[] totpSecret) {
        Enrollment {
            totpSecret = totpSecret.clone();
        }

        @Override
        public byte[] totpSecret() {
            return totpSecret.clone();
        }

        @Override
        public String toString() {
            return "Enrollment[" + username + ", " + role + "]";
        }
    }

    /** The first administrator's one-time credentials, handed over out-of-band (never logged). */
    record BootstrapCredentials(String username, char[] oneTimePassword, byte[] totpSecret) {
        BootstrapCredentials {
            oneTimePassword = oneTimePassword.clone();
            totpSecret = totpSecret.clone();
        }

        @Override
        public char[] oneTimePassword() {
            return oneTimePassword.clone();
        }

        @Override
        public byte[] totpSecret() {
            return totpSecret.clone();
        }

        @Override
        public String toString() {
            return "BootstrapCredentials[" + username + "]";
        }
    }

    private record AddressFailures(int count, Instant firstFailure) {
    }

    private static final int MIN_PASSWORD_CHARS = 12;
    private static final int MAX_PASSWORD_CHARS = 128;
    private static final String GENERIC_SIGN_IN_FAILURE =
            "Sign-in failed: the username, password, or authenticator code is incorrect.";
    private static final String LOCKED_MESSAGE =
            "This account is locked after too many failed sign-ins. Please contact the bank.";

    private final BankConfig config;
    private final UserDirectory users;
    private final PasswordHasher hasher;
    private final AuditLog audit;
    private final Clock clock;

    // CWE-366 (Race Condition within a Thread): sessions and
    // per-address failure counts are shared by every request thread, so they live in
    // ConcurrentHashMaps and are only updated with atomic operations (put, remove, compute).
    private final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AddressFailures> addressFailures = new ConcurrentHashMap<>();
    private final AtomicBoolean bootstrapAvailable = new AtomicBoolean(true);

    AuthService(BankConfig config, UserDirectory users, PasswordHasher hasher, AuditLog audit, Clock clock) {
        this.config = config;
        this.users = users;
        this.hasher = hasher;
        this.audit = audit;
        this.clock = clock;
    }

    // ------------------------------------------------------------------ enrollment

    /**
     * Creates the very first administrator. Works exactly once.
     */
    BootstrapCredentials bootstrapAdministrator() {
        // CWE-272 (Least Privilege Violation): creating an administrator out of thin air is a
        // startup-only power. compareAndSet() lets it run once; after that the bank permanently
        // gives up the ability, so nothing in the running system can mint new administrators.
        if (!bootstrapAvailable.compareAndSet(true, false)) {
            audit.record(Event.BOOTSTRAP, Outcome.DENIED, "system", "localhost", "administrator bootstrap attempted again");
            throw new BankException.AccessDenied("The first administrator has already been created.");
        }
        // CWE-1188 (Initialization of Resource with an Insecure Default): there is no default
        // admin password like "admin" or "changeme". The first administrator gets a random
        // one-time password and must replace it before their session can do anything else.
        char[] oneTimePassword = SecureRandomSource.passphrase();
        Enrollment enrollment = enroll("admin", "Administrator", Role.ADMIN, oneTimePassword, true, "system", "localhost");
        audit.record(Event.BOOTSTRAP, Outcome.SUCCESS, "system", "localhost",
                "first administrator created with a one-time password");
        return new BootstrapCredentials(enrollment.username(), oneTimePassword, enrollment.totpSecret());
    }

    /**
     * Self-service sign-up for customers.
     *
     * @param form non-secret form fields (username, displayName). The password is passed
     *             separately as a char[] so it can be wiped after use.
     */
    Enrollment registerCustomer(ClientRequest request, Map<String, String> form, char[] password) {
        requireTls(request, "Registration");
        // CWE-842 (Placement of User into Incorrect Group): the role for a self-registered user is
        // decided here, on the server, and is always CUSTOMER. A "role" field in the sign-up form
        // (or anything else the client sends) is never used to choose a group; it's logged as
        // suspicious and ignored. Staff roles can only be given by an administrator
        // (AdminService.createStaff), from a fixed list.
        if (form.containsKey("role")) {
            audit.record(Event.SUSPICIOUS_INPUT, Outcome.DENIED, "anonymous", request.remoteAddress(),
                    "registration form tried to choose its own role; ignored");
        }
        return enroll(form.get("username"), form.get("displayName"), Role.CUSTOMER, password, false,
                "anonymous", request.remoteAddress());
    }

    /** Shared by customer registration and staff creation. The role always comes from server code. */
    Enrollment enroll(String rawUsername, String displayName, Role role, char[] password,
                      boolean passwordChangeRequired, String actor, String source) {
        String username = Validation.canonicalUsername(rawUsername);
        Validation.require(Validation.DISPLAY_NAME, displayName, "Display name");
        if (users.isTaken(username)) {
            throw new BankException.InvalidInput("That username is not available.");
        }
        checkPasswordPolicy(username, password);
        byte[] totpSecret = Totp.newSecret();
        User user = users.add(username, displayName, role, hasher.hash(password), totpSecret, passwordChangeRequired);
        audit.record(role == Role.CUSTOMER ? Event.USER_REGISTERED : Event.STAFF_CREATED, Outcome.SUCCESS,
                actor, source, "user " + user.username() + " enrolled as " + role);
        return new Enrollment(user.id(), user.username(), role, totpSecret);
    }

    // ------------------------------------------------------------------ sign-in

    Session login(ClientRequest request, String rawUsername, char[] password, String totpCode) {
        requireTls(request, "Sign-in");
        // CWE-348 (Use of Less Trusted Source): throttling and auditing use the address of the
        // actual network connection. The X-Forwarded-For header is ignored because the client
        // writes it; an attacker could set it to an internal address (or a new address for every
        // guess) to dodge the per-address limit.
        String source = request.remoteAddress();
        Instant now = clock.instant();

        if (isAddressBlocked(source, now)) {
            audit.record(Event.ADDRESS_THROTTLED, Outcome.DENIED, "-", source,
                    "sign-in refused: too many recent failures from this address");
            throw new BankException.AuthenticationFailed(
                    "Too many failed sign-in attempts from this network address. Try again later.");
        }

        Optional<User> found = users.find(rawUsername);
        if (found.isEmpty()) {
            hasher.verifyAgainstDummy(password);
            recordAddressFailure(source, now);
            // CWE-779: the attempted name isn't logged; people sometimes type a password into it.
            audit.record(Event.LOGIN_FAILURE, Outcome.FAILURE, "unknown", source, "no such user");
            throw new BankException.AuthenticationFailed(GENERIC_SIGN_IN_FAILURE);
        }

        User user = found.get();
        User.CredentialCheck result = user.checkCredentials(hasher, password, totpCode, now,
                config.get(Setting.MAX_FAILED_LOGINS_PER_ACCOUNT));
        if (result != User.CredentialCheck.OK) {
            recordAddressFailure(source, now);
            // CWE-431 (Missing Handler): this is a switch EXPRESSION over an enum with no default,
            // so the compiler refuses to build the program if a new CredentialCheck value is ever
            // added without deciding how to handle it here.
            String reason = switch (result) {
                case FAILED -> "wrong password or authenticator code";
                case NOW_LOCKED -> "wrong password or authenticator code; limit reached";
                case LOCKED -> "account is locked";
                case OK -> throw new IllegalStateException("A successful check can't reach this branch.");
            };
            audit.record(Event.LOGIN_FAILURE, Outcome.FAILURE, user.username(), source, reason);
            if (result == User.CredentialCheck.NOW_LOCKED) {
                audit.record(Event.ACCOUNT_LOCKED, Outcome.SUCCESS, user.username(), source,
                        "sign-in locked after repeated failures");
            }
            throw new BankException.AuthenticationFailed(
                    result == User.CredentialCheck.LOCKED ? LOCKED_MESSAGE : GENERIC_SIGN_IN_FAILURE);
        }
        return openSession(user, source, now);
    }

    void logout(Session session) {
        requireActive(session, true);
        sessions.remove(session.token(), session);
        audit.record(Event.LOGOUT, Outcome.SUCCESS, session.username(), session.origin(), "signed out");
    }

    // ------------------------------------------------------------------ password change

    Session changePassword(Session session, char[] currentPassword, char[] newPassword, String totpCode) {
        requireActive(session, true);
        User user = users.findById(session.userId())
                .orElseThrow(() -> new BankException.AuthenticationFailed("Your session is not valid. Please sign in again."));
        Instant now = clock.instant();
        // CWE-620 (Unverified Password Change): being signed in is not enough to change the
        // password. Someone who walks up to an unlocked computer, or steals a session token, still
        // has to prove they know the CURRENT password and have the user's phone (a fresh
        // authenticator code). Wrong guesses here count toward the same lockout as sign-in.
        User.CredentialCheck check = user.checkCredentials(hasher, currentPassword, totpCode, now,
                config.get(Setting.MAX_FAILED_LOGINS_PER_ACCOUNT));
        if (check != User.CredentialCheck.OK) {
            audit.record(Event.PASSWORD_CHANGE_FAILED, Outcome.FAILURE, user.username(), session.origin(),
                    "current password or authenticator code was wrong");
            if (check == User.CredentialCheck.NOW_LOCKED) {
                audit.record(Event.ACCOUNT_LOCKED, Outcome.SUCCESS, user.username(), session.origin(),
                        "sign-in locked after repeated failures");
            }
            throw new BankException.AuthenticationFailed(
                    "Password not changed: the current password or authenticator code is incorrect.");
        }
        if (Arrays.equals(currentPassword, newPassword)) {
            throw new BankException.InvalidInput("The new password must be different from the current one.");
        }
        checkPasswordPolicy(user.username(), newPassword);
        user.replacePassword(hasher.hash(newPassword));
        int signedOut = endAllSessions(user.id());
        audit.record(Event.PASSWORD_CHANGED, Outcome.SUCCESS, user.username(), session.origin(),
                "password changed; " + signedOut + " session(s) signed out");
        return openSession(user, session.origin(), now);
    }

    // ------------------------------------------------------------------ sessions and permissions

    Session requireActive(Session session) {
        return requireActive(session, false);
    }

    boolean hasPermission(Session session, Permission permission) {
        requireActive(session);
        return session.role().has(permission) || PrivilegeContext.grants(session, permission);
    }

    void authorize(Session session, Permission permission, String action) {
        if (!hasPermission(session, permission)) {
            audit.record(Event.PERMISSION_DENIED, Outcome.DENIED, session.username(), session.origin(),
                    action + " (needs " + permission + ")");
            throw new BankException.AccessDenied("You are not allowed to " + action + ".");
        }
    }

    private Session requireActive(Session session, boolean allowPendingPasswordChange) {
        Session current = session == null ? null : sessions.get(session.token());
        if (current == null || current != session) {
            throw new BankException.AuthenticationFailed("Your session is not valid. Please sign in again.");
        }
        if (!clock.instant().isBefore(session.expiresAt())) {
            sessions.remove(session.token(), session);
            audit.record(Event.SESSION_EXPIRED, Outcome.SUCCESS, session.username(), session.origin(),
                    "session timed out");
            throw new BankException.AuthenticationFailed("Your session has expired. Please sign in again.");
        }
        if (session.passwordChangeRequired() && !allowPendingPasswordChange) {
            audit.record(Event.PERMISSION_DENIED, Outcome.DENIED, session.username(), session.origin(),
                    "action attempted before replacing one-time password");
            throw new BankException.AccessDenied("You must replace your one-time password before doing anything else.");
        }
        return session;
    }

    private Session openSession(User user, String source, Instant now) {
        // CWE-331: the session token is 256 bits from SecureRandom, so it can't be guessed.
        Duration timeout = Duration.ofMinutes(config.get(Setting.SESSION_TIMEOUT_MINUTES));
        Session session = new Session(SecureRandomSource.token(), user.id(), user.username(), user.role(),
                source, now.plus(timeout), user.passwordChangeRequired());
        sessions.put(session.token(), session);
        audit.record(Event.LOGIN_SUCCESS, Outcome.SUCCESS, user.username(), source,
                session.passwordChangeRequired()
                        ? "signed in; one-time password must be replaced"
                        : "signed in with password + authenticator code");
        return session;
    }

    private int endAllSessions(String userId) {
        List<Session> mine = sessions.values().stream().filter(s -> s.userId().equals(userId)).toList();
        // CWE-1095: a for-each over a fixed snapshot; nothing in the body changes what is looped over.
        for (Session session : mine) {
            sessions.remove(session.token(), session);
        }
        return mine.size();
    }

    // ------------------------------------------------------------------ helpers

    private void requireTls(ClientRequest request, String action) {
        // CWE-1188: encrypted connections are required, and there's no setting to turn that off.
        if (!request.tls()) {
            audit.record(Event.INSECURE_CONNECTION_REJECTED, Outcome.DENIED, "-", request.remoteAddress(),
                    action + " attempted over an unencrypted connection");
            throw new BankException.AccessDenied(action + " is only available over an encrypted (TLS) connection.");
        }
    }

    private Duration addressBlockWindow() {
        return Duration.ofMinutes(config.get(Setting.ADDRESS_BLOCK_MINUTES));
    }

    private boolean isAddressBlocked(String address, Instant now) {
        AddressFailures failures = addressFailures.get(address);
        return failures != null
                && failures.count() >= config.get(Setting.MAX_FAILED_LOGINS_PER_ADDRESS)
                && now.isBefore(failures.firstFailure().plus(addressBlockWindow()));
    }

    private void recordAddressFailure(String address, Instant now) {
        // CWE-366: compute() reads, updates, and stores the counter as one atomic step, so two
        // failed sign-ins at the same moment can't both read "2" and both write "3".
        addressFailures.compute(address, (key, previous) -> {
            if (previous == null || !now.isBefore(previous.firstFailure().plus(addressBlockWindow()))) {
                return new AddressFailures(1, now);
            }
            return new AddressFailures(previous.count() + 1, previous.firstFailure());
        });
    }

    private static void checkPasswordPolicy(String username, char[] password) {
        if (password == null || password.length < MIN_PASSWORD_CHARS || password.length > MAX_PASSWORD_CHARS) {
            throw new BankException.InvalidInput("Passwords must be 12 to 128 characters long.");
        }
        if (String.valueOf(password).toLowerCase(Locale.ROOT).contains(username)) {
            throw new BankException.InvalidInput("Passwords must not contain the username.");
        }
    }
}
