/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: Transaction.java
 *
 * Immutable record of one account transaction and the enum of transaction types.
 */

package securebank;

import java.time.Instant;

/**
 * One entry in an account's history. Records are immutable, so a Transaction handed to a caller
 * can't be altered to rewrite history.
 */
record Transaction(String id, Instant time, Type type, long amountCents, long balanceAfterCents, String memo) {

    enum Type {
        DEPOSIT, WITHDRAWAL, TRANSFER_IN, TRANSFER_OUT, PAYROLL_CREDIT, INTEREST, FEE;

        boolean isCredit() {
            // CWE-431 (Missing Handler): an exhaustive switch expression with no default. If a new
            // transaction type is added, the program won't compile until someone decides whether
            // it adds or removes money, so there is never an unhandled case at runtime.
            return switch (this) {
                case DEPOSIT, TRANSFER_IN, PAYROLL_CREDIT, INTEREST -> true;
                case WITHDRAWAL, TRANSFER_OUT, FEE -> false;
            };
        }

        String label() {
            return switch (this) {
                case DEPOSIT -> "Deposit";
                case WITHDRAWAL -> "Withdrawal";
                case TRANSFER_IN -> "Transfer in";
                case TRANSFER_OUT -> "Transfer out";
                case PAYROLL_CREDIT -> "Payroll";
                case INTEREST -> "Interest";
                case FEE -> "Service fee";
            };
        }
    }
}
