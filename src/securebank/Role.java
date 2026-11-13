/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: Role.java
 *
 * Enum of staff and customer roles and the minimal set of permissions each one has.
 */

package securebank;

import java.util.EnumSet;
import java.util.Set;

/**
 * The jobs people have at SecureBank, and exactly what each job may do.
 */
enum Role {

    // CWE-267 (Privilege Defined With Unsafe Actions): every role gets only the actions that job
    // needs, and the dangerous combinations are split between roles (separation of duties):
    //  - Tellers handle cash but can't move money between customers' accounts or read the audit log.
    //  - Managers approve large withdrawals but can't approve their own, and nobody holds
    //    LARGE_CASH_WITHDRAWAL permanently.
    //  - Auditors can read the audit log but can't touch money.
    //  - Administrators manage staff and settings but can't view or move customers' money.
    CUSTOMER(EnumSet.of(
            Permission.MANAGE_OWN_ACCOUNTS,
            Permission.VIEW_OWN_ACCOUNTS,
            Permission.TRANSFER_OWN_FUNDS,
            Permission.EXPORT_OWN_STATEMENT)),
    TELLER(EnumSet.of(
            Permission.VIEW_ANY_ACCOUNT,
            Permission.TELLER_CASH)),
    MANAGER(EnumSet.of(
            Permission.VIEW_ANY_ACCOUNT,
            Permission.TELLER_CASH,
            Permission.APPROVE_LARGE_WITHDRAWAL,
            Permission.UNLOCK_CUSTOMER,
            Permission.IMPORT_BATCH,
            Permission.RUN_MONTH_END)),
    AUDITOR(EnumSet.of(
            Permission.VIEW_AUDIT_LOG)),
    ADMIN(EnumSet.of(
            Permission.MANAGE_STAFF,
            Permission.MANAGE_CONFIG));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        // CWE-375: an immutable copy, so nobody can add a permission to a role at runtime.
        this.permissions = Set.copyOf(permissions);
    }

    boolean has(Permission permission) {
        return permissions.contains(permission);
    }

    Set<Permission> permissions() {
        return permissions;
    }
}
