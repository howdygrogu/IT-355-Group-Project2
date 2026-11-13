/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: Money.java
 *
 * Helpers for storing money as whole cents, formatting it, and validating amounts.
 */

package securebank;

import java.math.BigDecimal;
import java.util.Locale;

/** Money is stored as a whole number of cents, so there are no floating-point rounding errors. */
final class Money {

    static final long MAX_SINGLE_AMOUNT_CENTS = 100_000_000L; // $1,000,000.00

    private Money() {
    }

    static long dollars(long wholeDollars) {
        return Math.multiplyExact(wholeDollars, 100L);
    }

    static String format(long cents) {
        // CWE-134: constant format string; the amount is only ever an argument.
        return String.format(Locale.US, "$%,.2f", BigDecimal.valueOf(cents, 2));
    }

    static long requireValidAmount(long cents) {
        if (cents <= 0 || cents > MAX_SINGLE_AMOUNT_CENTS) {
            throw new BankException.InvalidInput("Amount must be between $0.01 and $1,000,000.00.");
        }
        return cents;
    }
}
