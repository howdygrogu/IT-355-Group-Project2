/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: ClientRequest.java
 *
 * Record describing an incoming request: its real connection address, TLS status, and headers.
 */

package securebank;

import java.util.Map;
import java.util.Objects;

/**
 * What the server knows about one incoming request.
 *
 * @param remoteAddress the address of the network connection itself, as reported by the socket
 * @param tls           whether the connection is encrypted
 * @param headers       whatever HTTP headers the client chose to send (fully client-controlled)
 */
record ClientRequest(String remoteAddress, boolean tls, Map<String, String> headers) {

    // CWE-348 (Use of Less Trusted Source): a request carries two sources for "who is calling":
    // the connection's real remoteAddress, which the server observes, and headers such as
    // X-Forwarded-For, which the client can set to anything. SecureBank only ever uses
    // remoteAddress for throttling and auditing. Headers are kept for completeness but are
    // never trusted for security decisions (there are no trusted proxies in this deployment).

    ClientRequest {
        Objects.requireNonNull(remoteAddress, "remoteAddress");
        // CWE-375: copy the caller's map so they can't change our request after creating it.
        headers = Map.copyOf(headers);
    }

    static ClientRequest secure(String remoteAddress) {
        return new ClientRequest(remoteAddress, true, Map.of());
    }
}
