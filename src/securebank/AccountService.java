/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: AccountService.java
 *
 * Service for opening accounts, deposits, withdrawals, transfers, manager approvals, and month-end processing.
 */

package securebank;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import securebank.AuditLog.Event;
import securebank.AuditLog.Outcome;
import securebank.BankConfig.Setting;

/**
 * Opening accounts, moving money, and month-end processing.
 */
final class AccountService {

    record StatementData(AccountSummary summary, List<Transaction> history) {
        StatementData {
            history = List.copyOf(history);
        }
    }

    record MonthEndLine(String maskedAccount, String product, String kind, long amountCents) {
    }

    private final AuthService auth;
    private final AuditLog audit;
    private final BankConfig config;
    private final Clock clock;

    // CWE-366 (listed in our report as CWE-336, Race Condition within a Thread): accounts are
    // opened and used from many threads, so the account table is a ConcurrentHashMap and new
    // account numbers are claimed with the atomic putIfAbsent().
    private final ConcurrentHashMap<String, Account> accounts = new ConcurrentHashMap<>();

    AccountService(AuthService auth, AuditLog audit, BankConfig config, Clock clock) {
        this.auth = auth;
        this.audit = audit;
        this.config = config;
        this.clock = clock;
    }

    // ------------------------------------------------------------------ customer actions

    AccountSummary openAccount(Session session, AccountType type) {
        auth.authorize(session, Permission.MANAGE_OWN_ACCOUNTS, "open accounts");
        // CWE-1095 (Loop Condition Value Update within the Loop): "attempt" is only changed by
        // the loop header and the limit is a constant, so this always ends after at most five
        // tries. The account number generated inside the body never affects the loop condition.
        for (int attempt = 0; attempt < 5; attempt++) {
            String accountId = "SB-" + SecureRandomSource.digits(10);
            Account account = newAccount(type, accountId, session.userId());
            if (accounts.putIfAbsent(accountId, account) == null) {
                return account.summary();
            }
        }
        throw new IllegalStateException("Could not allocate a unique account number.");
    }

    private static Account newAccount(AccountType type, String accountId, String ownerId) {
        // CWE-1062: the code that knows about the subclasses is here, outside the class hierarchy.
        // CWE-431: an exhaustive switch expression; a new AccountType won't compile until handled.
        return switch (type) {
            case CHECKING -> new CheckingAccount(accountId, ownerId);
            case SAVINGS -> new SavingsAccount(accountId, ownerId);
        };
    }

    List<AccountSummary> myAccounts(Session session) {
        auth.authorize(session, Permission.VIEW_OWN_ACCOUNTS, "view your accounts");
        // CWE-375: snapshots in an unmodifiable list (Stream.toList() can't be changed).
        return accounts.values().stream()
                .filter(account -> account.ownerId().equals(session.userId()))
                .map(Account::summary)
                .sorted(Comparator.comparing(AccountSummary::id))
                .toList();
    }

    AccountSummary viewAccount(Session session, String accountId) {
        return accessible(session, accountId, Permission.VIEW_OWN_ACCOUNTS, Permission.VIEW_ANY_ACCOUNT,
                "view this account").summary();
    }

    List<Transaction> history(Session session, String accountId) {
        return accessible(session, accountId, Permission.VIEW_OWN_ACCOUNTS, Permission.VIEW_ANY_ACCOUNT,
                "view this account's history").history();
    }

    void renameAccount(Session session, String accountId, String nickname) {
        Account account = accessible(session, accountId, Permission.MANAGE_OWN_ACCOUNTS, null, "rename this account");
        Validation.require(Validation.NICKNAME, nickname, "Nickname");
        locked(account, () -> {
            account.rename(nickname);
            return null;
        });
    }

    void transfer(Session session, String fromAccountId, String toAccountId, long cents, String memo) {
        Account from = accessible(session, fromAccountId, Permission.TRANSFER_OWN_FUNDS, null,
                "move money out of this account");
        Account to = existing(toAccountId);
        if (from == to) {
            throw new BankException.InvalidInput("Choose two different accounts.");
        }
        Money.requireValidAmount(cents);
        Validation.require(Validation.MEMO, memo, "Memo");

        // CWE-413 (Improper Resource Locking): a transfer changes two accounts, so it holds BOTH
        // accounts' locks for the whole check-debit-credit sequence. The locks are always taken in
        // the same order (lowest account number first), so a transfer A->B and a transfer B->A
        // running at the same time can't each grab one lock and wait forever for the other.
        Account first = from.id().compareTo(to.id()) < 0 ? from : to;
        Account second = first == from ? to : from;
        first.lock().lock();
        try {
            second.lock().lock();
            try {
                Instant now = clock.instant();
                to.requireCanCredit(cents);
                from.debit(Transaction.Type.TRANSFER_OUT, cents, memo, now);
                to.credit(Transaction.Type.TRANSFER_IN, cents, memo, now);
            } finally {
                second.lock().unlock();
            }
        } finally {
            first.lock().unlock();
        }
    }

    StatementData statementData(Session session, String accountId) {
        Account account = accessible(session, accountId, Permission.EXPORT_OWN_STATEMENT, null,
                "export a statement for this account");
        return locked(account, () -> new StatementData(account.summary(), account.history()));
    }

    // ------------------------------------------------------------------ branch staff actions

    Transaction tellerDeposit(Session teller, String accountId, long cents, String memo) {
        auth.authorize(teller, Permission.TELLER_CASH, "handle cash deposits");
        Account account = existing(accountId);
        Money.requireValidAmount(cents);
        Validation.require(Validation.MEMO, memo, "Memo");
        return locked(account, () -> account.credit(Transaction.Type.DEPOSIT, cents, memo, clock.instant()));
    }

    Transaction tellerWithdrawal(Session teller, String accountId, long cents, String memo) {
        auth.authorize(teller, Permission.TELLER_CASH, "handle cash withdrawals");
        Account account = existing(accountId);
        Money.requireValidAmount(cents);
        Validation.require(Validation.MEMO, memo, "Memo");
        long limit = Money.dollars(config.get(Setting.TELLER_CASH_LIMIT_DOLLARS));
        boolean large = cents > limit;
        if (large) {
            auth.authorize(teller, Permission.LARGE_CASH_WITHDRAWAL,
                    "pay out more than " + Money.format(limit) + " in cash without manager approval");
        }
        Transaction withdrawal = locked(account,
                () -> account.debit(Transaction.Type.WITHDRAWAL, cents, memo, clock.instant()));
        if (large) {
            audit.record(Event.LARGE_WITHDRAWAL, Outcome.SUCCESS, teller.username(), teller.origin(),
                    Money.format(cents) + " cash from " + AuditLog.maskAccount(accountId));
        }
        return withdrawal;
    }

    /**
     * Runs {@code action} with the teller temporarily allowed to make one large cash withdrawal,
     * after a different, signed-in manager approves it.
     */
    <T> T withManagerApproval(Session teller, Session manager, String reason, Supplier<T> action) {
        auth.authorize(manager, Permission.APPROVE_LARGE_WITHDRAWAL, "approve large withdrawals");
        auth.requireActive(teller);
        if (manager.userId().equals(teller.userId())) {
            audit.record(Event.PERMISSION_DENIED, Outcome.DENIED, manager.username(), manager.origin(),
                    "manager tried to approve their own transaction");
            throw new BankException.AccessDenied("A manager cannot approve their own transaction.");
        }
        Validation.require(Validation.MEMO, reason, "Approval reason");
        audit.record(Event.PRIVILEGE_ELEVATED, Outcome.SUCCESS, teller.username(), teller.origin(),
                "large cash withdrawal approved by " + manager.username() + ": " + reason);
        // CWE-270 (Privilege Context Switching Error): the extra permission is switched on only
        // inside runElevated(), which always switches it back off in a finally block. The audit
        // entry below is also in a finally block, so the log shows the privilege being removed
        // even when the approved action fails (for example, insufficient funds).
        try {
            return PrivilegeContext.runElevated(teller, EnumSet.of(Permission.LARGE_CASH_WITHDRAWAL), action);
        } finally {
            audit.record(Event.PRIVILEGE_RESTORED, Outcome.SUCCESS, teller.username(), teller.origin(),
                    "temporary large-withdrawal permission removed");
        }
    }

    void creditFromBatch(Session manager, String accountId, long cents, String memo) {
        auth.authorize(manager, Permission.IMPORT_BATCH, "import payroll batches");
        Account account = existing(accountId);
        locked(account, () -> account.credit(Transaction.Type.PAYROLL_CREDIT, cents, memo, clock.instant()));
    }

    List<MonthEndLine> runMonthEnd(Session manager) {
        auth.authorize(manager, Permission.RUN_MONTH_END, "run month-end processing");
        List<Account> snapshot = accounts.values().stream().sorted(Comparator.comparing(Account::id)).toList();
        List<MonthEndLine> lines = new ArrayList<>();
        // CWE-1095: a for-each over a fixed, immutable snapshot. The body adds to a different list
        // and never changes what's being looped over, so it can't skip or repeat accounts.
        for (Account account : snapshot) {
            Transaction adjustment = locked(account, () -> applyMonthEnd(account));
            if (adjustment != null) {
                lines.add(new MonthEndLine(AuditLog.maskAccount(account.id()), account.productName(),
                        adjustment.type().label(), adjustment.amountCents()));
            }
        }
        audit.record(Event.MONTH_END_RUN, Outcome.SUCCESS, manager.username(), manager.origin(),
                snapshot.size() + " accounts processed, " + lines.size() + " adjusted");
        return List.copyOf(lines);
    }

    /** Total money held by the bank, for reconciliation. */
    long totalOnDeposit(Session staff) {
        auth.authorize(staff, Permission.VIEW_ANY_ACCOUNT, "view bank-wide totals");
        long total = 0;
        for (Account account : List.copyOf(accounts.values())) {
            total = Math.addExact(total, account.balanceCents());
        }
        return total;
    }

    // ------------------------------------------------------------------ helpers

    private Transaction applyMonthEnd(Account account) {
        // CWE-1062: polymorphism. Each subclass decides its own adjustment; no type checks here.
        long adjustment = account.monthEndAdjustmentCents(account.balanceCents(), config);
        Instant now = clock.instant();
        if (adjustment > 0) {
            return account.credit(Transaction.Type.INTEREST, adjustment, "Monthly interest", now);
        }
        if (adjustment < 0) {
            return account.debit(Transaction.Type.FEE, -adjustment, "Monthly service fee", now);
        }
        return null;
    }

    /**
     * Returns the account if this session may act on it, and refuses otherwise.
     *
     * @param ownerPermission what the owner needs to do this
     * @param staffPermission what non-owners need instead, or null if only the owner may do it
     */
    private Account accessible(Session session, String accountId, Permission ownerPermission,
                               Permission staffPermission, String action) {
        auth.requireActive(session);
        Account account = Validation.isValid(Validation.ACCOUNT_ID, accountId) ? accounts.get(accountId) : null;
        // CWE-283 (Unverified Ownership): before anyone can see or use an account, we check that
        // the signed-in user's internal ID matches the account's ownerId. Knowing (or guessing)
        // an account number is not enough. Staff may only view other people's accounts if their
        // role allows it, and may never move money out of them. "Not found" and "not yours" get
        // the same message, so this can't be used to find out which account numbers exist.
        if (account != null && account.ownerId().equals(session.userId())) {
            auth.authorize(session, ownerPermission, action);
            return account;
        }
        if (account != null && staffPermission != null && auth.hasPermission(session, staffPermission)) {
            return account;
        }
        audit.record(Event.OWNERSHIP_VIOLATION, Outcome.DENIED, session.username(), session.origin(),
                action + " on " + AuditLog.maskAccount(accountId));
        throw new BankException.AccessDenied("Account not found, or you do not have access to it.");
    }

    private Account existing(String accountId) {
        Validation.require(Validation.ACCOUNT_ID, accountId, "Account number");
        Account account = accounts.get(accountId);
        if (account == null) {
            throw new BankException.InvalidInput("No such account.");
        }
        return account;
    }

    private static <T> T locked(Account account, Supplier<T> action) {
        // CWE-413: lock, act, and always unlock in a finally block, even if the action throws.
        account.lock().lock();
        try {
            return action.get();
        } finally {
            account.lock().unlock();
        }
    }
}
