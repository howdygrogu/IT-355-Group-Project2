/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: AdminService.java
 *
 * Service for creating staff, changing runtime settings, unlocking customers, and reading the audit log.
 */

package securebank;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import securebank.AuditLog.Event;
import securebank.AuditLog.Outcome;
import securebank.BankConfig.Setting;

/**
 * Staff management, runtime settings, unlocking customers, and reading the audit log.
 */
final class AdminService {

    // CWE-842 (Placement of User into Incorrect Group): administrators pick a staff member's role
    // from this fixed list, and ADMIN isn't on it, so no one can be put into the most powerful
    // group by mistake or through a crafted request.
    private static final Set<Role> ROLES_ADMIN_MAY_ASSIGN = Set.of(Role.TELLER, Role.MANAGER, Role.AUDITOR);

    private final AuthService auth;
    private final UserDirectory users;
    private final BankConfig config;
    private final AuditLog audit;

    AdminService(AuthService auth, UserDirectory users, BankConfig config, AuditLog audit) {
        this.auth = auth;
        this.users = users;
        this.config = config;
        this.audit = audit;
    }

    AuthService.Enrollment createStaff(Session admin, String username, String displayName, Role role, char[] password) {
        auth.authorize(admin, Permission.MANAGE_STAFF, "create staff accounts");
        if (!ROLES_ADMIN_MAY_ASSIGN.contains(role)) {
            audit.record(Event.PERMISSION_DENIED, Outcome.DENIED, admin.username(), admin.origin(),
                    "tried to create a user with role " + role);
            throw new BankException.AccessDenied("Administrators can only create teller, manager, and auditor accounts.");
        }
        return auth.enroll(username, displayName, role, password, false, admin.username(), admin.origin());
    }

    void changeSetting(Session admin, String key, String value) {
        // CWE-15 (External Control of System or Configuration Setting): changing a setting
        // requires the MANAGE_CONFIG permission, which only administrators have; the key must be
        // one of the few settings marked safe to change at runtime; and the value must be inside
        // that setting's safe range. Security switches such as two-factor sign-in don't exist as
        // settings at all, so no request can turn them off.
        auth.authorize(admin, Permission.MANAGE_CONFIG, "change system settings");
        Optional<Setting> setting = Setting.forKey(key);
        if (setting.isEmpty() || !setting.get().runtimeEditable) {
            audit.record(Event.CONFIG_CHANGE_REJECTED, Outcome.DENIED, admin.username(), admin.origin(),
                    "'" + key + "' is not changeable at runtime");
            throw new BankException.AccessDenied("'" + key + "' cannot be changed while the bank is running.");
        }
        try {
            config.applyRuntimeChange(setting.get(), value);
        } catch (BankException rejected) {
            audit.record(Event.CONFIG_CHANGE_REJECTED, Outcome.DENIED, admin.username(), admin.origin(),
                    "'" + key + "' rejected value: " + rejected.getMessage());
            throw rejected;
        }
        audit.record(Event.CONFIG_CHANGED, Outcome.SUCCESS, admin.username(), admin.origin(),
                key + " set to " + config.get(setting.get()));
    }

    void unlockCustomer(Session manager, String username) {
        auth.authorize(manager, Permission.UNLOCK_CUSTOMER, "unlock customer sign-ins");
        User customer = users.find(username)
                .filter(user -> user.role() == Role.CUSTOMER)
                .orElseThrow(() -> new BankException.InvalidInput("No such customer."));
        customer.unlock();
        audit.record(Event.ACCOUNT_UNLOCKED, Outcome.SUCCESS, manager.username(), manager.origin(),
                "unlocked sign-in for " + customer.username() + " after verifying identity");
    }

    List<AuditLog.Entry> readAuditLog(Session auditor, int maxEntries) {
        auth.authorize(auditor, Permission.VIEW_AUDIT_LOG, "read the audit log");
        return audit.recent(maxEntries);
    }
}
