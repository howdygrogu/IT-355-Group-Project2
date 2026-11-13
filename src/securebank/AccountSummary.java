/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: AccountSummary.java
 *
 * Immutable record holding a read-only snapshot of an account's details and balance.
 */

package securebank;

/**
 * A read-only snapshot of an account, which is what callers outside AccountService receive.
 */
record AccountSummary(String id, String product, String nickname, long balanceCents) {
    // CWE-375 (Returning a Mutable Object to an Untrusted Caller): callers never get the live
    // Account object, whose balance and history they could change. They get this immutable
    // record instead; changing a copy can't affect the bank's real data.
}
