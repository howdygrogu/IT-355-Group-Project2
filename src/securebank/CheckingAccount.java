/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: CheckingAccount.java
 *
 * Checking account subclass that charges a monthly fee below a minimum balance.
 */

package securebank;

import securebank.BankConfig.Setting;

/** An everyday account with a monthly fee when the balance falls below a minimum. */
final class CheckingAccount extends Account {

    CheckingAccount(String id, String ownerId) {
        super(id, ownerId);
    }

    @Override
    String productName() {
        return "Everyday Checking";
    }

    @Override
    long monthEndAdjustmentCents(long currentBalanceCents, BankConfig config) {
        // CWE-1062: checking-specific rules live in the child class; the parent just calls this.
        long minimum = Money.dollars(config.get(Setting.CHECKING_MINIMUM_BALANCE_DOLLARS));
        if (currentBalanceCents >= minimum) {
            return 0;
        }
        long fee = config.get(Setting.CHECKING_MONTHLY_FEE_CENTS);
        return -Math.min(fee, currentBalanceCents);
    }
}
