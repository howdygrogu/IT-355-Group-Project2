/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: AuthenticatorApp.java
 *
 * Simulated phone authenticator app that produces the user's current one-time code for the demo.
 */

package securebank;

import java.time.Clock;

/**
 * Simulates the authenticator app on a person's phone. Only the demo uses this class; the
 * bank itself only ever checks codes (see Totp and User).
 */
final class AuthenticatorApp {

    private final byte[] secret;
    private final Clock clock;

    AuthenticatorApp(byte[] secret, Clock clock) {
        // CWE-375: keep our own copy so the enrollment data can't change our secret later.
        this.secret = secret.clone();
        this.clock = clock;
    }

    String currentCode() {
        return Totp.codeAt(secret, Totp.stepAt(clock.instant()));
    }
}
