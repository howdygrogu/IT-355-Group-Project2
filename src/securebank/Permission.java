/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: Permission.java
 *
 * Enum of the individual actions that can be granted to a role.
 */

package securebank;

/**
 * Individual actions that can be granted to a role.
 */
enum Permission {
    // Customers, on their own accounts only
    MANAGE_OWN_ACCOUNTS,
    VIEW_OWN_ACCOUNTS,
    TRANSFER_OWN_FUNDS,
    EXPORT_OWN_STATEMENT,

    // Branch staff
    VIEW_ANY_ACCOUNT,
    TELLER_CASH,
    APPROVE_LARGE_WITHDRAWAL,
    UNLOCK_CUSTOMER,
    IMPORT_BATCH,
    RUN_MONTH_END,

    /**
     * Paying out cash above the teller limit. No role has this permanently: it is only ever
     * granted for a single transaction, after a second manager approves (see PrivilegeContext).
     */
    LARGE_CASH_WITHDRAWAL,

    // Oversight and administration
    VIEW_AUDIT_LOG,
    MANAGE_STAFF,
    MANAGE_CONFIG

    // CWE-267 (Privilege Defined With Unsafe Actions): the list is deliberately small and
    // specific. There is no "ALL" wildcard, no permission that edits or deletes audit log
    // entries (the log is append-only for everyone), and no permission that lets anyone read
    // passwords, authenticator secrets, or session tokens.
}
