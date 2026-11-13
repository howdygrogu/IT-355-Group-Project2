/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: Account.java
 *
 * Abstract base class for bank accounts, holding the balance, nickname, history, and per-account lock.
 */

package securebank;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Behavior shared by every kind of bank account.
 */
abstract class Account {

    // CWE-1062 (Parent Class with References to Child Class): this parent class never mentions
    // CheckingAccount or SavingsAccount; there are no instanceof checks, casts, or "if checking
    // then..." branches. Anything that differs between account types is an abstract method each
    // subclass implements (productName, monthEndAdjustmentCents). New account types can be
    // added without editing this class, and changing a subclass can't break the parent.
    // Choosing which subclass to create lives in AccountService, not here.

    private final String id;
    private final String ownerId;

    // CWE-413 (Improper Resource Locking): balance, nickname, and history are only touched while
    // this account's lock is held. Every method that changes them calls requireLockHeld(), so
    // forgetting to lock is caught immediately instead of silently corrupting a balance.
    //
    // CWE-366 (Race Condition within a Thread): because of that
    // lock, two threads can never interleave a "read balance, check it, write new balance"
    // sequence on the same account, so no update is ever lost.
    private final ReentrantLock lock = new ReentrantLock();
    private long balanceCents;
    private String nickname;
    private final List<Transaction> history = new ArrayList<>();

    protected Account(String id, String ownerId) {
        this.id = id;
        this.ownerId = ownerId;
    }

    final String id() {
        return id;
    }

    final String ownerId() {
        return ownerId;
    }

    /** The lock that guards this account. Only AccountService uses it. */
    final ReentrantLock lock() {
        return lock;
    }

    final long balanceCents() {
        lock.lock();
        try {
            return balanceCents;
        } finally {
            lock.unlock();
        }
    }

    final AccountSummary summary() {
        lock.lock();
        try {
            return new AccountSummary(id, productName(), nickname, balanceCents);
        } finally {
            lock.unlock();
        }
    }

    final List<Transaction> history() {
        lock.lock();
        try {
            // CWE-375 (Returning a Mutable Object to an Untrusted Caller): return an unmodifiable
            // copy, never the live list. A caller that tries to add, remove, or clear entries gets
            // an UnsupportedOperationException, and the real history is untouched.
            return List.copyOf(history);
        } finally {
            lock.unlock();
        }
    }

    final void rename(String newNickname) {
        requireLockHeld();
        nickname = newNickname;
    }

    /** Throws if crediting {@code cents} would overflow the balance. Call before moving money. */
    final void requireCanCredit(long cents) {
        requireLockHeld();
        Math.addExact(balanceCents, cents);
    }

    final Transaction credit(Transaction.Type type, long cents, String memo, Instant at) {
        requireLockHeld();
        if (!type.isCredit()) {
            throw new IllegalArgumentException(type + " is not a credit.");
        }
        balanceCents = Math.addExact(balanceCents, cents);
        return recordTransaction(type, cents, memo, at);
    }

    final Transaction debit(Transaction.Type type, long cents, String memo, Instant at) {
        requireLockHeld();
        if (type.isCredit()) {
            throw new IllegalArgumentException(type + " is not a debit.");
        }
        // The balance check and the subtraction happen under the same lock, so another thread
        // can't spend the money between "check" and "subtract".
        if (cents > balanceCents) {
            throw new BankException.InsufficientFunds("Insufficient funds.");
        }
        balanceCents -= cents;
        return recordTransaction(type, cents, memo, at);
    }

    private Transaction recordTransaction(Transaction.Type type, long cents, String memo, Instant at) {
        Transaction transaction = new Transaction("T-" + SecureRandomSource.base32(12), at, type, cents, balanceCents, memo);
        history.add(transaction);
        return transaction;
    }

    private void requireLockHeld() {
        if (!lock.isHeldByCurrentThread()) {
            throw new IllegalStateException("Account " + AuditLog.maskAccount(id) + " was changed without holding its lock.");
        }
    }

    /** The product name shown on statements. */
    abstract String productName();

    /**
     * The month-end change for this account type: positive for interest, negative for a fee,
     * zero for nothing.
     */
    abstract long monthEndAdjustmentCents(long currentBalanceCents, BankConfig config);
}
