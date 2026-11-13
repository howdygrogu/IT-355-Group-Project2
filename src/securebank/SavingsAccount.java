/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: SavingsAccount.java
 *
 * Savings account subclass that earns monthly interest.
 */

package securebank;

import securebank.BankConfig.Setting;

/** A savings account that earns monthly interest. */
final class SavingsAccount extends Account {

    SavingsAccount(String id, String ownerId) {
        super(id, ownerId);
    }

    @Override
    String productName() {
        return "High-Yield Savings";
    }

    @Override
    long monthEndAdjustmentCents(long currentBalanceCents, BankConfig config) {
        // CWE-1062: savings-specific rules live in the child class; the parent just calls this.
        long basisPoints = config.get(Setting.SAVINGS_INTEREST_BASIS_POINTS);
        return Math.multiplyExact(currentBalanceCents, basisPoints) / 10_000;
    }
}
