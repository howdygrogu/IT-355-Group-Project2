/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: PrivilegeContext.java
 *
 * Per-thread temporary permission elevation that is always removed when the action ends.
 */

package securebank;

import java.util.Set;
import java.util.function.Supplier;

/**
 * Temporarily grants a session extra permissions for one action, then takes them away again.
 */
final class PrivilegeContext {

    private record Elevation(Session session, Set<Permission> granted) {
    }

    // CWE-366 (CWE-336, Race Condition within a Thread): the elevation is
    // stored per thread, not in a shared field, so a manager's approval for one teller's
    // transaction can never leak into a transaction running on another thread at the same time.
    private static final ThreadLocal<Elevation> CURRENT = new ThreadLocal<>();

    private PrivilegeContext() {
    }

    static <T> T runElevated(Session session, Set<Permission> extra, Supplier<T> action) {
        // CWE-270 (Privilege Context Switching Error): the previous context is saved before the
        // switch and restored in a finally block, so the extra permissions are removed whether the
        // action succeeds, is refused, or throws an exception partway through. The elevation is
        // also tied to this one session object, so it can't be used by anyone else.
        Elevation previous = CURRENT.get();
        CURRENT.set(new Elevation(session, Set.copyOf(extra)));
        try {
            return action.get();
        } finally {
            if (previous == null) {
                CURRENT.remove();
            } else {
                CURRENT.set(previous);
            }
        }
    }

    static boolean grants(Session session, Permission permission) {
        Elevation elevation = CURRENT.get();
        return elevation != null && elevation.session() == session && elevation.granted().contains(permission);
    }
}
