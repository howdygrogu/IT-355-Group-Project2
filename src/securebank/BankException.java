/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: BankException.java
 *
 * Exception types the bank reports to callers, with safe user-facing messages.
 */

package securebank;

/**
 * Errors that SecureBank reports to callers. Messages are written for the person using the
 * bank: they never contain stack traces, file paths, passwords, or other internal details.
 */
class BankException extends RuntimeException {

    BankException(String message) {
        super(message);
    }

    /** Input that isn't in an accepted format, or a request that makes no sense. */
    static final class InvalidInput extends BankException {
        InvalidInput(String message) {
            super(message);
        }
    }

    /** The caller is signed in but isn't allowed to do this. */
    static final class AccessDenied extends BankException {
        AccessDenied(String message) {
            super(message);
        }
    }

    /** Sign-in failed, or the session is missing, expired, or ended. */
    static final class AuthenticationFailed extends BankException {
        AuthenticationFailed(String message) {
            super(message);
        }
    }

    static final class InsufficientFunds extends BankException {
        InsufficientFunds(String message) {
            super(message);
        }
    }
}
