/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: SimulatedClock.java
 *
 * Thread-safe clock the demo can move forward to show code windows and session timeouts.
 */

package securebank;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A clock the demo can move forward, so it can show 30-second authenticator codes and
 * session timeouts without actually waiting. The bank's services only see a java.time.Clock.
 */
final class SimulatedClock extends Clock {

    // CWE-366 (listed in our report as CWE-336, Race Condition within a Thread): many threads
    // read the time while the demo moves it forward, so the current instant is kept in an
    // AtomicReference. Every reader sees a complete, up-to-date value.
    private final AtomicReference<Instant> now;
    private final ZoneId zone;

    SimulatedClock(Instant start, ZoneId zone) {
        this(new AtomicReference<>(start), zone);
    }

    private SimulatedClock(AtomicReference<Instant> now, ZoneId zone) {
        this.now = now;
        this.zone = zone;
    }

    void advance(Duration amount) {
        if (amount.isNegative()) {
            throw new IllegalArgumentException("The clock only moves forward.");
        }
        now.updateAndGet(current -> current.plus(amount));
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId newZone) {
        return new SimulatedClock(now, newZone);
    }

    @Override
    public Instant instant() {
        return now.get();
    }
}
