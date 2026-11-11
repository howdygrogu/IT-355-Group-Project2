/*
 * CweDemo.java - Educational demo of 30 common weaknesses (CWEs).
 *
 * Every section shows a VULNERABLE version and a FIXED version, then runs both
 * so you can see the difference. Everything is simulated and self-contained
 * (JDK only, Java 11+). Secrets are fake. Do NOT copy the "vulnerable" code
 * into real projects.
 *
 * Run:  java CweDemo.java        (or: javac CweDemo.java && java CweDemo)
 */
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.*;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CweDemo {

    // ------------------------------------------------------------------ helpers
    interface Demo { void run() throws Exception; }

    static void banner(int cwe, String title) {
        System.out.println("\n" + "=".repeat(72));
        System.out.println("CWE-" + cwe + ": " + title);
        System.out.println("=".repeat(72));
    }
    static void vuln(String m) { System.out.println("  [VULNERABLE] " + m); }
    static void safe(String m) { System.out.println("  [FIXED     ] " + m); }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    /** Salted, slow, one-way password hash (used by the "fixed" examples). */
    static byte[] hashPassword(String pw, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pw.toCharArray(), salt, 100_000, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    static void deleteQuietly(Path... paths) {
        for (Path p : paths) { try { Files.deleteIfExists(p); } catch (IOException ignored) { } }
    }

    // ------------------------------------------------- CWE-431: Missing Handler
    static int parseAgeBad(String s) {
        return Integer.parseInt(s);            // NumberFormatException: nobody catches it
    }
    static OptionalInt parseAgeFixed(String s) {
        try {
            int age = Integer.parseInt(s);
            return (age >= 0 && age <= 150) ? OptionalInt.of(age) : OptionalInt.empty();
        } catch (NumberFormatException e) {
            return OptionalInt.empty();        // handled: caller gets a defined result
        }
    }
    static void demo431() {
        banner(431, "Missing Handler");
        try { parseAgeBad("abc"); }
        catch (NumberFormatException e) { vuln("unhandled exception escapes and would crash the program: " + e.getMessage()); }
        safe("parseAgeFixed(\"abc\") -> " + parseAgeFixed("abc"));
    }

    // ------------------------------- CWE-289: Authentication Bypass by Alternate Name
    static boolean isBlockedBad(Path p, Path restricted) {
        return p.toString().equals(restricted.toString());   // matches only ONE spelling
    }
    static boolean isBlockedFixed(Path p, Path restricted) throws IOException {
        return p.toRealPath().equals(restricted.toRealPath());  // canonical form
    }
    static void demo289() throws Exception {
        banner(289, "Authentication Bypass by Alternate Name");
        Path base = Files.createTempDirectory("cwe289");
        Path dir = Files.createDirectory(base.resolve("secret"));
        Path restricted = Files.createFile(dir.resolve("payroll.txt"));
        Path alias = base.resolve("secret").resolve("..").resolve("secret").resolve("payroll.txt");
        try {
            vuln("direct path blocked? " + isBlockedBad(restricted, restricted));
            vuln("'../' alias blocked?  " + isBlockedBad(alias, restricted) + "  <-- bypass");
            safe("'../' alias blocked?  " + isBlockedFixed(alias, restricted));
        } finally { deleteQuietly(restricted, dir, base); }
    }

    // ------------------------------------------- CWE-480: Use of Incorrect Operator
    static final String ADMIN = "admin";
    static boolean isAdminBad(String role)   { return role == ADMIN; }      // compares references
    static boolean isAdminFixed(String role) { return ADMIN.equals(role); } // compares contents
    static void demo480() {
        banner(480, "Use of Incorrect Operator");
        String role = new String("admin");   // e.g. read from a request or database
        vuln("isAdminBad(new String(\"admin\"))   -> " + isAdminBad(role));
        safe("isAdminFixed(new String(\"admin\")) -> " + isAdminFixed(role));
    }

    // ------------------------------------------------- CWE-331: Insufficient Entropy
    static String tokenBad(long seed) {
        Random r = new Random(seed);          // predictable PRNG, guessable seed
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) sb.append(Integer.toHexString(r.nextInt(16)));
        return sb.toString();
    }
    static String tokenFixed() { return hex(randomBytes(8)); }   // CSPRNG
    static void demo331() {
        banner(331, "Insufficient Entropy");
        long seed = System.currentTimeMillis() / 1000;
        String victim = tokenBad(seed), attacker = tokenBad(seed);
        vuln("victim token " + victim + ", attacker regenerated " + attacker + ", match=" + victim.equals(attacker));
        safe("two SecureRandom tokens: " + tokenFixed() + " / " + tokenFixed());
    }

    // ----------------------------------------- CWE-625: Permissive Regular Expression
    static final String NAME_REGEX = "[a-z0-9]+\\.txt";
    static boolean validNameBad(String s)   { return Pattern.compile(NAME_REGEX).matcher(s).find(); } // substring match
    static boolean validNameFixed(String s) { return Pattern.matches("^" + NAME_REGEX + "$", s); }     // anchored, full match
    static void demo625() {
        banner(625, "Permissive Regular Expression");
        String evil = "../../etc/passwd; report.txt";
        vuln("\"" + evil + "\" accepted? " + validNameBad(evil));
        safe("\"" + evil + "\" accepted? " + validNameFixed(evil));
    }

    // ------------------------------- CWE-378: Temp File With Insecure Permissions
    static void demo378() throws Exception {
        banner(378, "Creation of Temporary File With Insecure Permissions");
        Path bad = Paths.get(System.getProperty("java.io.tmpdir"), "report_tmp_" + ProcessHandle.current().pid() + ".txt");
        Path good = null;
        try {
            Files.write(bad, "sensitive".getBytes());   // predictable name, default (umask) permissions
            vuln("permissions: " + PosixFilePermissions.toString(Files.getPosixFilePermissions(bad)) + " (others may read)");
            good = Files.createTempFile("report", ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            safe("permissions: " + PosixFilePermissions.toString(Files.getPosixFilePermissions(good)) + " (owner only)");
        } finally { deleteQuietly(bad); if (good != null) deleteQuietly(good); }
    }

    // ----------------- CWE-836: Use of Password Hash Instead of Password
    // CWE-836 happens when a system accepts the password HASH itself as the credential.
    // If the hash is what proves identity, then anyone who steals the hash (for example,
    // from a leaked database) can log in without ever knowing the real password
    // Hashing the password in the client doesn't help, because the
    // hash simply becomes the new password.
    static String sha256Hex(String s) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
    }
    static void demo836() throws Exception {
        banner(836, "Use of Password Hash Instead of Password for Authentication");
        String stored = sha256Hex("correct horse");               // client hashes, server stores it
        vuln("attacker with the leaked hash logs in without the password: " + stored.equals(stored));
        byte[] salt = randomBytes(16);
        byte[] dbHash = hashPassword("correct horse", salt);      // server hashes the real password
        safe("replaying leaked DB hash as password: "
                + MessageDigest.isEqual(hashPassword(hex(dbHash), salt), dbHash));
        safe("real password: " + MessageDigest.isEqual(hashPassword("correct horse", salt), dbHash));
    }

    // ----------------------------------------- CWE-798: Use of Hard-Coded Credentials
    // CWE-798 happens when a password, key, or other secret is written directly into the
    // source code. Anyone who gets the code or the compiled program (for example, by
    // decompiling the jar) can read it, and it can't be changed without rebuilding and
    // redeploying. It is also the same in every installation, so one leak exposes all of them.
    static final String HARDCODED_DB_PASSWORD = "demo-not-a-real-password"; // identical in every install
    static String dbPasswordBad() { return HARDCODED_DB_PASSWORD; }
    static String dbPasswordFixed() {
        String pw = System.getProperty("db.password", System.getenv("DB_PASSWORD")); // or a secrets manager
        if (pw == null) throw new IllegalStateException("db password not configured");
        return pw;
    }
    static void demo798() {
        banner(798, "Use of Hard-Coded Credentials");
        vuln("anyone decompiling the jar gets: \"" + dbPasswordBad() + "\"");
        System.setProperty("db.password", "per-install-" + hex(randomBytes(4)));  // simulates secrets manager
        safe("loaded from external configuration: \"" + dbPasswordFixed() + "\"");
        System.clearProperty("db.password");
    }

    // --------------------------------------------- CWE-348: Use of Less Trusted Source
    // The X-Forwarded-For header is set by the client, so an attacker can fake it to look like
    // an internal IP and pass an IP allow-list. The fix uses the real TCP connection address,
    // which the sender can't forge.
    static String clientIpBad(Map<String, String> headers, String peer) {
        return headers.getOrDefault("X-Forwarded-For", peer);   // attacker-controlled header
    }
    static String clientIpFixed(Map<String, String> headers, String peer) {
        return peer;                                           // from the TCP connection
    }
    static void demo348() {
        banner(348, "Use of Less Trusted Source");
        Map<String, String> h = Map.of("X-Forwarded-For", "10.0.0.1");
        vuln("IP allow-list sees: " + clientIpBad(h, "203.0.113.50") + " (spoofed internal address)");
        safe("IP allow-list sees: " + clientIpFixed(h, "203.0.113.50"));
    }

    // --------------------------------- CWE-842: Placement of User into Incorrect Group
    // Deciding a user's role by guessing from their username (anything containing "admin")
    // puts the wrong people in privileged groups, e.g. "badminton_fan" becomes an admin.
    // The fix looks up the role in an explicit role table and defaults to "user".
    static final Map<String, String> ROLE_TABLE = Map.of("alice", "admin", "bob", "user");
    static String groupBad(String user)   { return user.contains("admin") ? "admin" : "user"; }
    static String groupFixed(String user) { return ROLE_TABLE.getOrDefault(user, "user"); }
    static void demo842() {
        banner(842, "Placement of User into Incorrect Group");
        String name = "badminton_fan";
        vuln("\"" + name + "\" -> " + groupBad(name));
        safe("\"" + name + "\" -> " + groupFixed(name));
    }

    // -------------------------------------------- CWE-256: Plaintext Storage of a Password
    // Storing passwords as plain text means anyone who gets the database (a leak, a backup,
    // an insider) can read every password directly. The fix stores only a salted hash made
    // with a slow password hashing function (PBKDF2), which can't be reversed to the password.
    static void demo256() throws Exception {
        banner(256, "Plaintext Storage of a Password");
        Map<String, String> dbBad = Map.of("carol", "Tr0ub4dor&3");
        vuln("database dump reveals: " + dbBad);
        byte[] h = hashPassword("Tr0ub4dor&3", randomBytes(16));
        safe("database dump reveals: {carol=" + hex(h).substring(0, 24) + "...} (salted PBKDF2 hash)");
    }

    // ------------------------------------------------ CWE-272: Least Privilege Violation
    // A process that keeps extra privileges after it no longer needs them 
    //  gives an attacker far more power if it is compromised. The fix
    // drops every privilege except the one needed to serve requests right after startup.
    static class SimProcess {
        Set<String> privileges = new HashSet<>(Set.of("bind_low_port", "read_all_files", "write_all_files", "serve"));
        void dropPrivileges() { privileges = new HashSet<>(Set.of("serve")); }
        boolean can(String p) { return privileges.contains(p); }
    }
    static void demo272() {
        banner(272, "Least Privilege Violation");
        SimProcess bad = new SimProcess();          // binds port 80, keeps everything
        vuln("after startup, compromised process can read all files: " + bad.can("read_all_files"));
        SimProcess good = new SimProcess();
        good.dropPrivileges();                      // drop right after the privileged step
        safe("after dropPrivileges(), can read all files: " + good.can("read_all_files"));
    }

    // ----------------------------------------- CWE-308: Use of Single-factor Authentication
    static String totp(byte[] secret) throws Exception {
        long counter = System.currentTimeMillis() / 1000 / 30;
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(secret, "HmacSHA1"));
        byte[] h = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());
        int off = h[h.length - 1] & 0x0F;
        int bin = ((h[off] & 0x7F) << 24) | ((h[off + 1] & 0xFF) << 16) | ((h[off + 2] & 0xFF) << 8) | (h[off + 3] & 0xFF);
        return String.format("%06d", bin % 1_000_000);
    }
    static void demo308() throws Exception {
        banner(308, "Use of Single-factor Authentication");
        byte[] salt = randomBytes(16), pwHash = hashPassword("pa55word", salt), totpSecret = randomBytes(20);
        boolean passwordOk = MessageDigest.isEqual(hashPassword("pa55word", salt), pwHash);
        vuln("stolen password alone is enough: " + passwordOk);
        safe("stolen password, no second factor: " + (passwordOk && totp(totpSecret).equals("000000")));
        safe("password + valid TOTP code:         " + (passwordOk && totp(totpSecret).equals(totp(totpSecret))));
    }

    // ------------------------------- CWE-257: Storing Passwords in a Recoverable Format
    static final byte[] APP_KEY = "0123456789abcdef".getBytes();   // 128-bit key, still reversible
    static byte[] xor(byte[] data, byte[] key) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte) (data[i] ^ key[i % key.length]);
        return out;
    }
    static void demo257() {
        banner(257, "Storing Passwords in a Recoverable Format");
        byte[] stored = xor("Tr0ub4dor&3".getBytes(), APP_KEY);
        vuln("stored: " + hex(stored));
        vuln("anyone who obtains the key recovers: \"" + new String(xor(stored, APP_KEY)) + "\"");
        safe("store only a one-way salted hash (see CWE-256 fix); nothing to decrypt");
    }

    // ------------------------------------ CWE-270: Privilege Context Switching Error
    static class Session { String user = "guest"; }
    static void runAsBad(Session s, String user, Runnable task) {
        String previous = s.user;
        s.user = user;
        task.run();                       // if this throws, context is never reverted
        s.user = previous;
    }
    static void runAsFixed(Session s, String user, Runnable task) {
        String previous = s.user;
        s.user = user;
        try { task.run(); } finally { s.user = previous; }   // always restored
    }
    static void demo270() {
        banner(270, "Privilege Context Switching Error");
        Runnable boom = () -> { throw new IllegalStateException("task failed"); };
        Session s = new Session();
        try { runAsBad(s, "admin", boom); } catch (IllegalStateException ignored) { }
        vuln("after a failed admin task the session user is still: \"" + s.user + "\"");
        s = new Session();
        try { runAsFixed(s, "admin", boom); } catch (IllegalStateException ignored) { }
        safe("after a failed admin task the session user is: \"" + s.user + "\"");
    }

    // ------------------------------------------ CWE-260: Password in Configuration File
    static void demo260() throws Exception {
        banner(260, "Password in Configuration File");
        Path cfg = Files.createTempFile("app", ".properties");
        try {
            Files.write(cfg, "db.host=localhost\ndb.password=demo-config-password\n".getBytes());
            Properties p = new Properties();
            p.load(Files.newBufferedReader(cfg));
            vuln("anyone who can read " + cfg.getFileName() + " gets: \"" + p.getProperty("db.password") + "\"");
        } finally { deleteQuietly(cfg); }
        System.setProperty("app.db.password", hex(randomBytes(6)));   // simulates env var / secrets manager
        safe("config file holds only non-secrets; password comes from a secrets manager: "
                + System.getProperty("app.db.password").substring(0, 4) + "...");
        System.clearProperty("app.db.password");
    }

    // ----------------------------- CWE-375: Returning a Mutable Object to an Untrusted Caller
    static class PolicyBad {
        private final List<String> allowedHosts = new ArrayList<>(List.of("intranet.local"));
        List<String> getAllowedHosts() { return allowedHosts; }              // live internal reference
    }
    static class PolicyFixed {
        private final List<String> allowedHosts = new ArrayList<>(List.of("intranet.local"));
        List<String> getAllowedHosts() { return List.copyOf(allowedHosts); } // immutable copy
    }
    static void demo375() {
        banner(375, "Returning a Mutable Object to an Untrusted Caller");
        PolicyBad p = new PolicyBad();
        p.getAllowedHosts().add("evil.example");
        vuln("caller changed internal state: " + p.getAllowedHosts());
        PolicyFixed q = new PolicyFixed();
        try { q.getAllowedHosts().add("evil.example"); } catch (UnsupportedOperationException ignored) { }
        safe("internal state intact: " + q.getAllowedHosts());
    }

    // --------------------------------------- CWE-267: Privilege Defined With Unsafe Actions
    static final Map<String, Set<String>> ROLES_BAD =
            Map.of("backup_operator", Set.of("read_all", "write_backup", "delete_audit_log"));
    static final Map<String, Set<String>> ROLES_FIXED =
            Map.of("backup_operator", Set.of("read_all", "write_backup"));
    static void demo267() {
        banner(267, "Privilege Defined With Unsafe Actions");
        vuln("backup_operator may delete audit logs: " + ROLES_BAD.get("backup_operator").contains("delete_audit_log"));
        safe("backup_operator may delete audit logs: " + ROLES_FIXED.get("backup_operator").contains("delete_audit_log"));
    }

    // ----------------------------------------------------------------------------
    // CWE-336 (as titled in your notes): Race Condition within a Thread
    // Demonstrates a race condition when multiple threads update a shared counter. 
    // A compare an unsynchronized counter with a synchronized version
    // ----------------------------------------------------------------------------
    static class CounterBad {
        int value = 0;
        void inc() {
            int tmp = value;
            LockSupport.parkNanos(100_000);   // widens the race window so the bug is visible
            value = tmp + 1;
        }
    }
    static class CounterFixed extends CounterBad {
        @Override synchronized void inc() { super.inc(); }
    }
    static int hammer(CounterBad c, int threads, int perThread) throws InterruptedException {
        Thread[] ts = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            ts[i] = new Thread(() -> { for (int j = 0; j < perThread; j++) c.inc(); });
            ts[i].start();
        }
        for (Thread t : ts) t.join();
        return c.value;
    }
    static void demo336() throws Exception {
        banner(336, "Race Condition within a Thread (per your notes)");
        vuln("unsynchronized counter: " + hammer(new CounterBad(), 8, 50) + " (expected 400)");
        safe("synchronized counter:   " + hammer(new CounterFixed(), 8, 50) + " (expected 400)");
    }

    // ------------------------------- CWE-1062: Parent Class with References to Child Class
    // Demonstrates poor class design when a parent class directly references its child class
    // compares this with polymorphism, where the child class implements their own methods without the parent
    static class ShapeBad {
        String describe() {
            if (this instanceof CircleBad c) return "circle r=" + c.radius;   // parent knows its child
            return "unknown shape";
        }
    }
    static class CircleBad extends ShapeBad { double radius; CircleBad(double r) { radius = r; } }

    static abstract class Shape { abstract String describe(); }               // parent depends on nobody
    static class Circle extends Shape {
        double radius; Circle(double r) { radius = r; }
        @Override String describe() { return "circle r=" + radius; }
    }
    static void demo1062() {
        banner(1062, "Parent Class with References to Child Class");
        vuln("ShapeBad.describe() hard-codes CircleBad: " + new CircleBad(2).describe());
        safe("polymorphism, parent has no child references: " + new Circle(2).describe());
    }

    // ------------------------------------------------ CWE-620: Unverified Password Change
    // Demonstrates an unverified password change vulnerabilt where a user can change their password without proving their identity
    // the fixed version requieres the user to enter their current password before allowing a password change
    static class UserStore {
        byte[] salt = randomBytes(16);
        byte[] pw;
        UserStore() throws Exception { pw = hashPassword("old-password", salt); }
        boolean changeBad(String newPw) throws Exception {
            salt = randomBytes(16); pw = hashPassword(newPw, salt); return true;   // no proof of identity
        }
        boolean changeFixed(String current, String newPw) throws Exception {
            if (!MessageDigest.isEqual(hashPassword(current, salt), pw)) return false;
            salt = randomBytes(16); pw = hashPassword(newPw, salt); return true;
        }
    }
    static void demo620() throws Exception {
        banner(620, "Unverified Password Change");
        vuln("hijacked session changes password with no proof: " + new UserStore().changeBad("attacker-pw"));
        safe("wrong current password:   " + new UserStore().changeFixed("guess", "attacker-pw"));
        safe("correct current password: " + new UserStore().changeFixed("old-password", "new-pw"));
    }

    // --------------------------------------------- CWE-261: Weak Encoding for Password
    // Demonstrates weak password protection using Base64 encoding and a short XOR key.
    // Shows how easily passwords can be decoded or brute-forced and recommends strong password hashing algorithms.
    static void demo261() {
        banner(261, "Weak Encoding for Password");
        String enc = Base64.getEncoder().encodeToString("Tr0ub4dor&3".getBytes());
        vuln("base64 'protected' password " + enc + " -> \""
                + new String(Base64.getDecoder().decode(enc)) + "\"");
        byte[] weak = xor("Tr0ub4dor&3".getBytes(), new byte[]{0x5A});     // 8-bit key
        String cracked = null;
        for (int k = 0; k < 256 && cracked == null; k++) {
            String guess = new String(xor(weak, new byte[]{(byte) k}));
            if (guess.startsWith("Tr0")) cracked = guess;
        }
        vuln("1-byte key brute-forced instantly -> \"" + cracked + "\"");
        safe("use a strong one-way hash (PBKDF2/scrypt/argon2/bcrypt); if encryption is ever required, "
                + "use vetted ciphers with >=128-bit keys");
    }

    // ----------------------------- CWE-1095: Loop Condition Value Update within the Loop
    // Demonstrates a loop-control vulnerability where modifying the index and loop boundary inside the loop can cause skipped elements or incorrect execution.
    // The fixed version uses streams to filter negative numbers without manually modifying loop control variables.
    static List<Integer> removeNegativesBad(List<Integer> input) {
        List<Integer> items = new ArrayList<>(input);
        int i = 0, n = items.size();
        while (i < n) {
            if (items.get(i) < 0) {
                items.remove(i);
                n--;               // loop bound AND index both changed inside the body;
            } else {               // miss one update and you skip items or loop forever
                i++;
            }
        }
        return items;
    }
    static List<Integer> removeNegativesFixed(List<Integer> input) {
        return input.stream().filter(x -> x >= 0).toList();       // no hidden loop-control mutation
    }
    static void demo1095() {
        banner(1095, "Loop Condition Value Update within the Loop");
        List<Integer> data = List.of(3, -1, -2, 5, -7, 8);
        vuln("works, but fragile and hard to audit: " + removeNegativesBad(data));
        safe("clear and maintainable: " + removeNegativesFixed(data));
    }

    // ----------------------------- CWE-778 / CWE-779: Insufficient / Excessive Logging
    // Demonstrates insufficient logging and excessive logging.
    // The first example compares silently ignored failed login attempts with properly recorded security events.
    // The second example compares excessive logs containing sensitive information with concise logs that avoid exposing passwords.
    static class Capture extends Handler {
        final StringBuilder sb = new StringBuilder();
        @Override public void publish(LogRecord r) { sb.append(r.getLevel()).append(' ').append(r.getMessage()).append('\n'); }
        @Override public void flush() { }
        @Override public void close() { }
    }
    static Logger makeLogger(String name, Capture cap) {
        Logger lg = Logger.getLogger(name);
        lg.setUseParentHandlers(false);
        lg.setLevel(Level.INFO);
        lg.addHandler(cap);
        return lg;
    }
    static void demo778() {
        banner(778, "Insufficient Logging");
        Capture bad = new Capture();
        makeLogger("bad778", bad);          // vulnerable: failed login silently ignored
        vuln("failed login for 'mallory' from 198.51.100.7 -> log has " + bad.sb.length() + " bytes");
        Capture good = new Capture();
        makeLogger("good778", good).warning("auth_failure user=mallory ip=198.51.100.7 reason=bad_password");
        safe("log entry: " + good.sb.toString().trim());
    }
    static void demo779() {
        banner(779, "Logging of Excessive Data");
        Capture bad = new Capture(), good = new Capture();
        Logger lb = makeLogger("bad779", bad), lg = makeLogger("good779", good);
        for (int i = 0; i < 50; i++) {
            lb.info("request " + i + " body=" + "x".repeat(200) + " password=hunter2-demo");
            lg.info("request " + i + " method=POST path=/login size=200");
        }
        vuln("50 requests -> " + bad.sb.length() + " bytes of noisy logs, with passwords in them");
        safe("50 requests -> " + good.sb.length() + " bytes, concise and secret-free");
    }

    // ------------------------ CWE-1188: Initialization of Resource with an Insecure Default
    static class ServerBad {
        boolean debug = true, tls = false;
        String adminPassword = "admin";
    }
    static class ServerFixed {
        final boolean debug = false, tls = true;       // secure defaults
        final String adminPassword;
        ServerFixed(String adminPassword) {            // must be supplied, and be strong
            if (adminPassword == null || adminPassword.length() < 12)
                throw new IllegalArgumentException("admin password too short");
            this.adminPassword = adminPassword;
        }
    }
    static void demo1188() {
        banner(1188, "Initialization of Resource with an Insecure Default");
        ServerBad s = new ServerBad();
        vuln("defaults: debug=" + s.debug + " tls=" + s.tls + " adminPassword=\"" + s.adminPassword + "\"");
        try { new ServerFixed("admin"); }
        catch (IllegalArgumentException e) { safe("weak password rejected: " + e.getMessage()); }
        ServerFixed f = new ServerFixed(hex(randomBytes(8)));
        safe("secure defaults: debug=" + f.debug + " tls=" + f.tls);
    }

    // ------------------- CWE-15: External Control of System or Configuration Setting
    static final Set<String> USER_EDITABLE = Set.of("theme", "language");
    static Map<String, Object> defaultConfig() {
        return new HashMap<>(Map.of("theme", "light", "language", "en", "require_auth", true));
    }
    static void updateBad(Map<String, Object> cfg, Map<String, Object> in) { cfg.putAll(in); }  // any key!
    static void updateFixed(Map<String, Object> cfg, Map<String, Object> in) {
        in.forEach((k, v) -> { if (USER_EDITABLE.contains(k)) cfg.put(k, v); });                // allow-list
    }
    static void demo15() {
        banner(15, "External Control of System or Configuration Setting");
        Map<String, Object> payload = Map.of("theme", "dark", "require_auth", false);
        Map<String, Object> cfg = defaultConfig();
        updateBad(cfg, payload);
        vuln("user turned off authentication: require_auth=" + cfg.get("require_auth"));
        cfg = defaultConfig();
        updateFixed(cfg, payload);
        safe("allow-list kept it on: require_auth=" + cfg.get("require_auth") + ", theme=" + cfg.get("theme"));
    }

    // ------------------------------------------------------ CWE-283: Unverified Ownership
    record Doc(String owner, String text) { }
    static final Map<Integer, Doc> DOCS = Map.of(
            1, new Doc("alice", "alice's private notes"),
            2, new Doc("bob", "bob's private notes"));
    static String getDocBad(int id, String user) { return DOCS.get(id).text(); }   // owner never checked
    static String getDocFixed(int id, String user) {
        Doc d = DOCS.get(id);
        if (!d.owner().equals(user)) throw new SecurityException("not your document");
        return d.text();
    }
    static void demo283() {
        banner(283, "Unverified Ownership");
        vuln("bob reads doc 1: \"" + getDocBad(1, "bob") + "\"");
        try { getDocFixed(1, "bob"); }
        catch (SecurityException e) { safe("bob reads doc 1: SecurityException(" + e.getMessage() + ")"); }
    }

    // --------------------------- CWE-134: Use of Externally-Controlled Format String
    static final String API_SECRET = "demo-api-secret-123";
    static String renderBad(String userFormat, String name) {
        return String.format(userFormat, name, API_SECRET);     // attacker controls the format
    }
    static String renderFixed(String name) {
        return String.format("Hello, %s!", name);               // format string is a constant
    }
    static void demo134() {
        banner(134, "Use of Externally-Controlled Format String");
        vuln("format \"%2$s\" leaks: \"" + renderBad("%2$s", "eve") + "\"");
        try { renderBad("%d %d %d", "eve"); }
        catch (IllegalFormatException e) { vuln("format \"%d %d %d\" crashes the request: " + e.getClass().getSimpleName()); }
        safe("constant format: \"" + renderFixed("%2$s") + "\"");
    }

    // ------------------------------------------------- CWE-413: Improper Resource Locking
    static class Account {
        int balance;
        final Object lock = new Object();
        Account(int b) { balance = b; }
        void withdrawBad(int amt) {
            synchronized (new Object()) {                // brand-new lock per call: protects nothing
                if (balance >= amt) { LockSupport.parkNanos(1_000_000); balance -= amt; }
            }
        }
        void withdrawFixed(int amt) {
            synchronized (lock) {                        // one shared lock for check-and-update
                if (balance >= amt) { LockSupport.parkNanos(1_000_000); balance -= amt; }
            }
        }
    }
    static int withdrawAll(boolean fixed) throws InterruptedException {
        Account acct = new Account(500);
        Thread[] ts = new Thread[10];
        for (int i = 0; i < ts.length; i++) {
            ts[i] = new Thread(() -> { if (fixed) acct.withdrawFixed(100); else acct.withdrawBad(100); });
            ts[i].start();
        }
        for (Thread t : ts) t.join();
        return acct.balance;
    }
    static void demo413() throws Exception {
        banner(413, "Improper Resource Locking");
        vuln("10 x withdraw(100) from 500 -> balance " + withdrawAll(false) + " (overdrawn)");
        safe("10 x withdraw(100) from 500 -> balance " + withdrawAll(true));
    }

    // ------------------------------------------------------------------------ main
    public static void main(String[] args) throws Exception {
        System.out.println("CWE demonstration: vulnerable vs fixed code (educational, simulated)");
        Demo[] demos = {
            CweDemo::demo431, CweDemo::demo289, CweDemo::demo480, CweDemo::demo331, CweDemo::demo625,
            CweDemo::demo378, CweDemo::demo836, CweDemo::demo798, CweDemo::demo348, CweDemo::demo842,
            CweDemo::demo256, CweDemo::demo272, CweDemo::demo308, CweDemo::demo257, CweDemo::demo270,
            CweDemo::demo260, CweDemo::demo375, CweDemo::demo267, CweDemo::demo336, CweDemo::demo1062,
            CweDemo::demo620, CweDemo::demo261, CweDemo::demo1095, CweDemo::demo778, CweDemo::demo779,
            CweDemo::demo1188, CweDemo::demo15, CweDemo::demo283, CweDemo::demo134, CweDemo::demo413
        };
        for (Demo d : demos) d.run();
        System.out.println("\nDone: " + demos.length + " weaknesses demonstrated.");
    }
}
