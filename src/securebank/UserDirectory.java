/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: UserDirectory.java
 *
 * Thread-safe directory of users, looked up by canonical username or internal ID.
 */

package securebank;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Everyone who can sign in, looked up by canonical username or by internal user ID.
 */
final class UserDirectory {

    // CWE-366 (Race Condition within a Thread): registrations and
    // sign-ins happen on many threads, so users are kept in ConcurrentHashMaps. putIfAbsent()
    // checks and inserts in one atomic step, so two people registering the same name at the
    // same instant can't both succeed.
    private final ConcurrentHashMap<String, User> byUsername = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, User> byId = new ConcurrentHashMap<>();

    boolean isTaken(String rawUsername) {
        return byUsername.containsKey(Validation.canonicalUsername(rawUsername));
    }

    User add(String rawUsername, String displayName, Role role, PasswordHasher.StoredPassword password,
             byte[] totpSecret, boolean passwordChangeRequired) {
        // CWE-289: always store the canonical spelling, so look-alike spellings collide here.
        String username = Validation.canonicalUsername(rawUsername);
        // Internal IDs are random and never reused. Accounts, files, and sessions are tied to this
        // ID rather than the username, so there is only ever one name for the owner of anything.
        User user = new User("U-" + SecureRandomSource.base32(16), username, displayName, role,
                password, totpSecret, passwordChangeRequired);
        if (byUsername.putIfAbsent(username, user) != null) {
            throw new BankException.InvalidInput("That username is not available.");
        }
        byId.put(user.id(), user);
        return user;
    }

    Optional<User> find(String rawUsername) {
        try {
            return Optional.ofNullable(byUsername.get(Validation.canonicalUsername(rawUsername)));
        } catch (BankException.InvalidInput malformed) {
            // CWE-431 (Missing Handler): a malformed name is handled as "no such user", not left
            // to propagate as an unexpected error from the sign-in page.
            return Optional.empty();
        }
    }

    Optional<User> findById(String userId) {
        return userId == null ? Optional.empty() : Optional.ofNullable(byId.get(userId));
    }
}
