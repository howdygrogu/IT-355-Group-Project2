/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: Main.java
 *
 * Entry point that starts the bank and runs the scripted day-at-the-bank simulation and security checks.
 */

package securebank;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import securebank.BankConfig.Setting;

/**
 * SecureBank: IT 355 Group Project 2.
 *
 * A small online-banking back end (customers, tellers, managers, an auditor, and an
 * administrator) written to avoid the 30 CWEs from our report. This class runs a scripted
 * "day at the bank" where staff are set up, customers sign up and move money, attackers try
 * to exploit it, and the month is closed out. Every attack and in the script is expected to be
 * blocked, and the program checks that it was, exiting with status 1 if anything was exploited.
 *
 * Search the source for "CWE-" to find comments indicating where comment. README.md has an index of which CWE is handled in which file.
 *
 * <pre>
 *   javac -encoding UTF-8 -d out src/securebank/*.java
 *   java -cp out securebank.Main [settings-file] [--keep-data]
 * </pre>
 */
public final class Main {

    // Network addresses from the ranges reserved for documentation (RFC 5737).
    private static final String HEAD_OFFICE = "192.0.2.5";
    private static final String BRANCH = "192.0.2.10";
    private static final String ALICE_HOME = "198.51.100.23";
    private static final String BOB_HOME = "198.51.100.47";
    private static final String ATTACKER = "203.0.113.66";
    private static final String SECOND_ATTACKER = "203.0.113.91";

    /** A simulated person: the password they remember and the authenticator app on their phone. */
    private static final class DemoUser {
        private final String username;
        private final AuthenticatorApp phone;
        private char[] password;

        DemoUser(String username, char[] password, AuthenticatorApp phone) {
            this.username = username;
            this.password = password;
            this.phone = phone;
        }
    }

    private final SimulatedClock clock = new SimulatedClock(Instant.now().truncatedTo(ChronoUnit.SECONDS), ZoneOffset.UTC);
    private final Path configPath;
    private final Path dataRoot;
    private int checksPassed;
    private int checksFailed;

    private BankConfig config;
    private UserDirectory users;
    private AuthService auth;
    private AdminService admin;
    private AccountService accounts;
    private StatementService statements;
    private BatchImporter importer;

    private DemoUser adminUser;
    private DemoUser tina;
    private DemoUser maria;
    private DemoUser aaron;
    private DemoUser alice;
    private DemoUser bob;

    private Session tinaSession;
    private Session mariaSession;
    private Session aliceSession;
    private Session bobSession;

    private String aliceChecking;
    private String aliceSavings;
    private String bobChecking;
    private String leakedHash;

    private Main(Path configPath, Path dataRoot) {
        this.configPath = configPath;
        this.dataRoot = dataRoot;
    }

    public static void main(String[] args) {
        // CWE-431 (Missing Handler): a last-resort handler for every thread. If something truly
        // unexpected escapes, it's reported briefly (no stack trace or internal details for an
        // attacker to read) instead of the thread dying silently.
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> System.err.println(
                "Internal error in thread " + thread.getName() + " (" + error.getClass().getSimpleName()
                        + "); that operation was stopped."));

        boolean keepData = false;
        Path configPath = Paths.get("config", "securebank.properties");
        for (String arg : args) {
            if (arg.equals("--keep-data")) {
                keepData = true;
            } else {
                configPath = Paths.get(arg);
            }
        }

        int exitCode;
        Path dataRoot = null;
        try {
            installDeserializationFilter();
            dataRoot = SecureFiles.createOwnerOnlyTempDirectory("securebank-");
            exitCode = new Main(configPath, dataRoot).run();
        } catch (IOException | BankException | IllegalStateException e) {
            // CWE-431: expected failures (missing files, bad settings) end the program cleanly.
            System.err.println("SecureBank stopped: " + e.getMessage());
            exitCode = 1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("SecureBank was interrupted.");
            exitCode = 1;
        } finally {
            cleanUp(dataRoot, keepData);
        }
        System.exit(exitCode);
    }

    private static void installDeserializationFilter() {
        // CWE-502 (Deserialization of Untrusted Data): SecureBank never deserializes Java objects.
        // To make sure no library does it behind our backs, a process-wide filter rejects every
        // class ("!*"), so any ObjectInputStream in this JVM fails before building any object.
        try {
            ObjectInputFilter.Config.setSerialFilter(ObjectInputFilter.Config.createFilter("!*"));
        } catch (IllegalStateException alreadySet) {
            // CWE-431: someone already set a filter (for example with -Djdk.serialFilter); keep it.
            System.out.println("Note: a JVM-wide deserialization filter was already configured; keeping it.");
        }
    }

    private static void cleanUp(Path dataRoot, boolean keepData) {
        if (dataRoot == null) {
            return;
        }
        if (keepData) {
            System.out.println("Bank data (statements and audit log) kept in: " + dataRoot);
            return;
        }
        try {
            SecureFiles.deleteRecursively(dataRoot);
        } catch (IOException e) {
            System.err.println("Note: some temporary bank files could not be deleted.");
        }
    }

    // =====================================================================================
    // The scripted day at the bank
    // =====================================================================================

    private int run() throws IOException, InterruptedException {
        System.out.println("SecureBank: a day at the bank (simulated)");
        section("1. Starting the bank");
        startUp();
        section("2. Administrator setup");
        setUpStaff();
        section("3. Customers join and start banking");
        customersJoin();
        everydayBanking();
        section("4. Attacks on sign-in");
        signInAttacks();
        section("5. Everyone stays inside their own permissions");
        permissionBoundaries();
        section("6. Large cash withdrawal with manager approval");
        managerApproval();
        section("7. Monthly statements");
        statementFiles();
        section("8. Payroll batch import");
        payrollImport();
        section("9. Many transfers at the same time");
        concurrentTransfers();
        section("10. Month-end processing");
        monthEnd();
        section("11. Password changes and session timeouts");
        passwordsAndSessions();
        section("12. Audit log review");
        auditReview();

        section("Summary");
        System.out.println("  " + checksPassed + " security checks behaved as expected, " + checksFailed + " did not.");
        return checksFailed == 0 ? 0 : 1;
    }

    private void startUp() throws IOException {
        if (Files.isRegularFile(configPath)) {
            config = BankConfig.load(configPath);
            ok("Loaded settings from " + configPath + " (this file may not contain secrets)");
        } else {
            config = BankConfig.secureDefaults();
            ok("No settings file at " + configPath + "; using the secure built-in defaults");
        }
        for (Map.Entry<Setting, Integer> entry : config.snapshot().entrySet()) {
            info(entry.getKey().key + " = " + entry.getValue());
        }

        // Settings files that should be refused. The "password" below is a random throwaway value
        // that is never used for anything; it only exists to show the file being rejected.
        Path badSettings = SecureFiles.createOwnerOnlyTempFile(dataRoot, "bad-settings-", ".properties");
        try {
            Files.writeString(badSettings, "database.password=" + SecureRandomSource.base32(16) + "\n", StandardCharsets.UTF_8);
            expectBlocked("Starting with a settings file that contains a password", () -> loadSettings(badSettings));
            Files.writeString(badSettings, "auth.mfaRequired=false\n", StandardCharsets.UTF_8);
            expectBlocked("Starting with a settings file that tries to turn off two-factor sign-in", () -> loadSettings(badSettings));
            Files.writeString(badSettings, "auth.maxFailedLoginsPerAccount=1000\n", StandardCharsets.UTF_8);
            expectBlocked("Starting with a settings file that allows 1,000 password guesses", () -> loadSettings(badSettings));
        } finally {
            Files.deleteIfExists(badSettings);
        }

        KeyVault vault = KeyVault.fromEnvironment();
        ok(vault.isEphemeral()
                ? KeyVault.PEPPER_ENVIRONMENT_VARIABLE + " is not set, so a random pepper was generated for this run"
                : "Loaded the password pepper from the " + KeyVault.PEPPER_ENVIRONMENT_VARIABLE + " environment variable");
        PasswordHasher hasher = new PasswordHasher(vault.pepper());
        vault.seal();
        ok("Key vault sealed: from now on the running bank cannot read raw secrets");
        expectBlocked("Reading the pepper from the key vault after startup", vault::pepper);

        AuditLog audit = new AuditLog(SecureFiles.createOwnerOnlyDirectory(dataRoot.resolve("audit")), clock);
        users = new UserDirectory();
        auth = new AuthService(config, users, hasher, audit, clock);
        admin = new AdminService(auth, users, config, audit);
        accounts = new AccountService(auth, audit, config, clock);
        statements = new StatementService(accounts, auth, audit, clock, dataRoot);
        importer = new BatchImporter(accounts, auth, audit);
        audit.record(AuditLog.Event.STARTUP, AuditLog.Outcome.SUCCESS, "system", "localhost", "SecureBank started");
        ok("Services started; the audit log file is " + SecureFiles.describeAccess(audit.file()));
    }

    private void setUpStaff() {
        AuthService.BootstrapCredentials boot = auth.bootstrapAdministrator();
        adminUser = new DemoUser(boot.username(), boot.oneTimePassword(), new AuthenticatorApp(boot.totpSecret(), clock));
        ok("Created the first administrator with a random one-time password (there is no default password)");
        expectBlocked("Running the administrator bootstrap a second time", auth::bootstrapAdministrator);

        Session firstSession = signIn(adminUser, HEAD_OFFICE);
        ok("admin signed in with the one-time password and an authenticator code");
        expectBlocked("admin creating staff before replacing the one-time password",
                () -> admin.createStaff(firstSession, "tina", "Tina Torres", Role.TELLER, SecureRandomSource.passphrase()));
        char[] newPassword = SecureRandomSource.passphrase();
        Session adminSession = auth.changePassword(firstSession, adminUser.password, newPassword, freshCode(adminUser));
        adminUser.password = newPassword;
        ok("admin replaced the one-time password (needed the current password and a fresh authenticator code)");

        tina = enrollStaff(adminSession, "tina", "Tina Torres", Role.TELLER);
        maria = enrollStaff(adminSession, "maria", "Maria Okafor", Role.MANAGER);
        aaron = enrollStaff(adminSession, "aaron", "Aaron Fields", Role.AUDITOR);
        expectBlocked("admin creating a second administrator account",
                () -> admin.createStaff(adminSession, "eve", "Eve Evans", Role.ADMIN, SecureRandomSource.passphrase()));

        admin.changeSetting(adminSession, "session.timeoutMinutes", "10");
        ok("admin shortened sessions to 10 minutes (a setting that may change while running)");
        expectBlocked("Setting session.timeoutMinutes to 600",
                () -> admin.changeSetting(adminSession, "session.timeoutMinutes", "600"));
        expectBlocked("Changing auth.maxFailedLoginsPerAccount while the bank is running",
                () -> admin.changeSetting(adminSession, "auth.maxFailedLoginsPerAccount", "100"));
        expectBlocked("Turning off two-factor sign-in",
                () -> admin.changeSetting(adminSession, "auth.mfaRequired", "false"));
        auth.logout(adminSession);
        ok("admin signed out; administrator powers aren't left signed in while unused");
    }

    private void customersJoin() {
        alice = registerCustomer(Map.of("username", "alice", "displayName", "Alice Nguyen"), ALICE_HOME);
        bob = registerCustomer(Map.of("username", "bob", "displayName", "Bob Martinez", "role", "ADMIN"), BOB_HOME);
        info("(bob's sign-up form also said role=ADMIN; the bank ignored it)");

        expectBlocked("Registering 'ALICE', another spelling of an existing username",
                () -> auth.registerCustomer(ClientRequest.secure(ATTACKER),
                        Map.of("username", "ALICE", "displayName", "Fake Alice"), SecureRandomSource.passphrase()));
        expectBlocked("Registering a full-width Unicode look-alike of 'alice'",
                () -> auth.registerCustomer(ClientRequest.secure(ATTACKER),
                        Map.of("username", "ａｌｉｃｅ", "displayName", "Fake Alice"),
                        SecureRandomSource.passphrase()));
        expectBlocked("Registering over an unencrypted connection",
                () -> auth.registerCustomer(new ClientRequest(ATTACKER, false, Map.of()),
                        Map.of("username", "carol", "displayName", "Carol King"), SecureRandomSource.passphrase()));
        expectBlocked("Registering with a 6-character password",
                () -> auth.registerCustomer(ClientRequest.secure(ATTACKER),
                        Map.of("username", "carol", "displayName", "Carol King"), "abc123".toCharArray()));
    }

    private void everydayBanking() {
        aliceSession = signIn(alice, ALICE_HOME);
        bobSession = signIn(bob, BOB_HOME);
        tinaSession = signIn(tina, BRANCH);
        mariaSession = signIn(maria, BRANCH);
        ok("alice, bob, tina, and maria signed in (password + authenticator code each)");

        aliceChecking = accounts.openAccount(aliceSession, AccountType.CHECKING).id();
        aliceSavings = accounts.openAccount(aliceSession, AccountType.SAVINGS).id();
        bobChecking = accounts.openAccount(bobSession, AccountType.CHECKING).id();
        ok("alice opened checking and savings accounts; bob opened a checking account");

        accounts.tellerDeposit(tinaSession, aliceChecking, Money.dollars(2_500), "Cash deposit");
        accounts.tellerDeposit(tinaSession, bobChecking, Money.dollars(9_000), "Cash deposit");
        ok("tina (teller) deposited $2,500 for alice and $9,000 for bob");

        accounts.transfer(aliceSession, aliceChecking, aliceSavings, Money.dollars(400), "Rainy day fund %n%s");
        accounts.renameAccount(aliceSession, aliceSavings, "Rainy Day Fund");
        ok("alice moved $400 to savings (memo: \"Rainy day fund %n%s\") and named the account \"Rainy Day Fund\"");
        expectBlocked("Naming an account \"<script>alert(1)</script>\"",
                () -> accounts.renameAccount(aliceSession, aliceSavings, "<script>alert(1)</script>"));
        expectBlocked("Naming an account with a hidden line break (\"Savings\\nApproved\")",
                () -> accounts.renameAccount(aliceSession, aliceSavings, "Savings\nApproved"));

        for (AccountSummary summary : accounts.myAccounts(aliceSession)) {
            info(AuditLog.maskAccount(summary.id()) + "  " + summary.product() + "  " + Money.format(summary.balanceCents()));
        }
        List<Transaction> history = accounts.history(aliceSession, aliceChecking);
        expectBlocked("Erasing the transaction history list the bank handed back", history::clear);
        info("alice's checking account still has " + accounts.history(aliceSession, aliceChecking).size() + " transactions");
    }

    private void signInAttacks() {
        // The attacker sends a forged X-Forwarded-For header claiming to be inside the bank.
        ClientRequest spoofed = new ClientRequest(ATTACKER, true, Map.of("X-Forwarded-For", "10.0.0.5"));
        List<String> spellings = List.of("alice", "ALICE", " Alice ");
        int addressLimit = config.get(Setting.MAX_FAILED_LOGINS_PER_ADDRESS);
        for (int attempt = 1; attempt <= addressLimit; attempt++) {
            String spelling = spellings.get((attempt - 1) % spellings.size());
            char[] guess = ("Guess-" + SecureRandomSource.base32(10)).toCharArray();
            expectBlocked("Password guess #" + attempt + " from " + ATTACKER + " as '" + spelling
                    + "' (header claims 10.0.0.5)", () -> auth.login(spoofed, spelling, guess, wrongCode(alice)));
        }
        expectBlocked("Guess #" + (addressLimit + 1) + ": the REAL address is now throttled; the fake header doesn't help",
                () -> auth.login(spoofed, "alice", "Guess-again-please".toCharArray(), wrongCode(alice)));

        ClientRequest secondAttacker = ClientRequest.secure(SECOND_ATTACKER);
        expectBlocked("Signing in with alice's phished password but without her phone",
                () -> auth.login(secondAttacker, "alice", alice.password, wrongCode(alice)));
        leakedHash = users.find("alice").orElseThrow().storedHashForBreachDrill();
        expectBlocked("Signing in with alice's leaked password HASH (plus a valid code from her phone)",
                () -> auth.login(secondAttacker, "alice", leakedHash.toCharArray(), freshCode(alice)));

        if (users.find("alice").map(User::isLocked).orElse(false)) {
            ok("alice's sign-in locked itself after " + config.get(Setting.MAX_FAILED_LOGINS_PER_ACCOUNT)
                    + " failures (all spellings of her name counted toward the same account)");
            expectBlocked("alice herself signing in while her account is locked", () -> signIn(alice, ALICE_HOME));
            admin.unlockCustomer(mariaSession, "alice");
            ok("maria (manager) checked alice's ID at the branch and unlocked her sign-in");
        }
        aliceSession = signIn(alice, ALICE_HOME);
        ok("alice signed in again from home");
    }

    private void permissionBoundaries() {
        Session aaronSession = signIn(aaron, BRANCH);
        expectBlocked("bob viewing alice's checking account", () -> accounts.viewAccount(bobSession, aliceChecking));
        expectBlocked("bob moving money out of alice's checking account",
                () -> accounts.transfer(bobSession, aliceChecking, bobChecking, Money.dollars(100), "Thanks"));
        expectBlocked("bob exporting a statement for alice's account", () -> statements.exportStatement(bobSession, aliceChecking));
        expectBlocked("bob reading the audit log", () -> admin.readAuditLog(bobSession, 10));
        expectBlocked("tina (teller) moving money between customers' accounts",
                () -> accounts.transfer(tinaSession, aliceChecking, bobChecking, Money.dollars(100), "Oops"));
        expectBlocked("tina (teller) reading the audit log", () -> admin.readAuditLog(tinaSession, 10));
        expectBlocked("tina (teller) unlocking a customer", () -> admin.unlockCustomer(tinaSession, "bob"));
        expectBlocked("aaron (auditor) making a cash deposit",
                () -> accounts.tellerDeposit(aaronSession, bobChecking, Money.dollars(50), "Cash deposit"));
        expectBlocked("aaron (auditor) changing a setting",
                () -> admin.changeSetting(aaronSession, "teller.cashLimitDollars", "10000"));
        ok("tina can still look up bob's account for him at the counter: "
                + Money.format(accounts.viewAccount(tinaSession, bobChecking).balanceCents()));
        auth.logout(aaronSession);
    }

    private void managerApproval() {
        expectBlocked("tina paying bob $6,000 in cash without approval (teller limit is $5,000)",
                () -> accounts.tellerWithdrawal(tinaSession, bobChecking, Money.dollars(6_000), "Cash withdrawal"));
        expectBlocked("maria approving a $20,000 withdrawal, more than bob has",
                () -> accounts.withManagerApproval(tinaSession, mariaSession, "Car purchase",
                        () -> accounts.tellerWithdrawal(tinaSession, bobChecking, Money.dollars(20_000), "Car purchase")));
        expectBlocked("tina trying $6,000 again right after that failed approval (it must not linger)",
                () -> accounts.tellerWithdrawal(tinaSession, bobChecking, Money.dollars(6_000), "Cash withdrawal"));
        Transaction paid = accounts.withManagerApproval(tinaSession, mariaSession, "Car purchase",
                () -> accounts.tellerWithdrawal(tinaSession, bobChecking, Money.dollars(6_000), "Car purchase"));
        ok("With maria's approval, tina paid out " + Money.format(paid.amountCents())
                + "; bob's balance is now " + Money.format(paid.balanceAfterCents()));
        expectBlocked("tina paying out another $6,000 with the approval already used up",
                () -> accounts.tellerWithdrawal(tinaSession, bobChecking, Money.dollars(6_000), "Cash withdrawal"));
        expectBlocked("maria approving her own large withdrawal",
                () -> accounts.withManagerApproval(mariaSession, mariaSession, "Cash",
                        () -> accounts.tellerWithdrawal(mariaSession, bobChecking, Money.dollars(6_000), "Cash")));
    }

    private void statementFiles() throws IOException {
        String fileName = statements.exportStatement(aliceSession, aliceChecking);
        Path file = dataRoot.resolve("statements").resolve(aliceSession.userId()).resolve(fileName);
        ok("alice exported a statement: " + fileName);
        info("file access: " + SecureFiles.describeAccess(file));
        String text = statements.readStatement(aliceSession, fileName);
        ok("alice downloaded it again:");
        for (String line : text.lines().toList()) {
            System.out.println("              | " + line);
        }
        info("(the memo \"Rainy day fund %n%s\" printed exactly as typed; it was never used as a format string)");

        expectBlocked("alice requesting \"../" + bobSession.userId() + "/" + fileName + "\"",
                () -> statements.readStatement(aliceSession, "../" + bobSession.userId() + "/" + fileName));
        expectBlocked("alice requesting her own statement in capitals (Windows would open the same file)",
                () -> statements.readStatement(aliceSession, fileName.toUpperCase(Locale.ROOT)));
        expectBlocked("bob requesting alice's statement by its exact file name",
                () -> statements.readStatement(bobSession, fileName));
    }

    private void payrollImport() throws IOException {
        Path inbox = SecureFiles.createOwnerOnlyDirectory(dataRoot.resolve("inbox"));
        Path batch = SecureFiles.createOwnerOnlyTempFile(inbox, "payroll-", ".txt");
        String batchText = String.join("\n",
                "BATCH|ACME-PAYROLL-1114|" + LocalDate.now(clock),
                "# Employer: ACME Corp",
                "CREDIT|" + aliceChecking + "|320000|ACME payroll %s%n",
                "CREDIT|" + bobChecking + "|275000|ACME payroll",
                "CREDIT|SB-0000000000|100000|Unknown employee",
                "CREDIT|" + bobChecking + "|-50000|Negative amount",
                "CREDIT|" + aliceChecking + "|900000000|Far too large",
                "DEBIT|" + aliceChecking + "|5000|Debits are not allowed",
                "CREDIT|" + bobChecking + "|10000|Bonus; DROP TABLE accounts") + "\n";
        Files.writeString(batch, batchText, StandardCharsets.UTF_8);

        expectBlocked("tina (teller) importing the payroll batch", () -> importer.importPayroll(tinaSession, batch));
        BatchImporter.Result result = importer.importPayroll(mariaSession, batch);
        ok("maria imported batch " + result.batchId() + ": " + result.accepted() + " credits totaling "
                + Money.format(result.totalCents()) + " were accepted");
        for (String problem : result.rejected()) {
            info(problem);
        }
        check(result.accepted() == 2 && result.rejected().size() == 5,
                "Each bad line was rejected on its own, without stopping the good ones");

        Path serialized = SecureFiles.createOwnerOnlyTempFile(inbox, "payroll-", ".bin");
        Files.write(serialized, new byte[] {(byte) 0xAC, (byte) 0xED, 0x00, 0x05, 0x73, 0x72, 0x00, 0x11});
        expectBlocked("Importing a 'batch' that is really a serialized Java object",
                () -> importer.importPayroll(mariaSession, serialized));
    }

    private void concurrentTransfers() throws InterruptedException {
        long before = accounts.totalOnDeposit(mariaSession);
        int threads = 8;
        int transfersPerThread = 250;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<?>> tasks = new ArrayList<>();
        for (int task = 0; task < threads; task++) {
            boolean aliceSends = task % 2 == 0;
            tasks.add(pool.submit(() -> {
                for (int i = 0; i < transfersPerThread; i++) {
                    if (aliceSends) {
                        accounts.transfer(aliceSession, aliceChecking, bobChecking, 100, "Split the bill");
                    } else {
                        accounts.transfer(bobSession, bobChecking, aliceChecking, 100, "Split the bill");
                    }
                }
            }));
        }
        pool.shutdown();
        int failedTasks = 0;
        // CWE-431 (Missing Handler): every task's result is collected. A task that threw, or that
        // never finished, is counted and reported instead of being silently forgotten.
        for (Future<?> task : tasks) {
            try {
                task.get(60, TimeUnit.SECONDS);
            } catch (ExecutionException failed) {
                failedTasks++;
                info("a transfer task failed: " + failed.getCause().getMessage());
            } catch (TimeoutException stuck) {
                failedTasks++;
                task.cancel(true);
                info("a transfer task did not finish in time");
            }
        }
        if (!pool.awaitTermination(10, TimeUnit.SECONDS)) {
            pool.shutdownNow();
        }
        long after = accounts.totalOnDeposit(mariaSession);
        int total = threads * transfersPerThread;
        ok(total + " one-dollar transfers ran at once on " + threads + " threads, in both directions");
        check(failedTasks == 0, "No transfer deadlocked or failed");
        check(before == after, "No money was created or lost: the bank held " + Money.format(before)
                + " before and " + Money.format(after) + " after");
    }

    private void monthEnd() {
        List<AccountService.MonthEndLine> lines = accounts.runMonthEnd(mariaSession);
        ok("maria ran month-end processing:");
        for (AccountService.MonthEndLine line : lines) {
            info(line.maskedAccount() + "  " + line.product() + "  " + line.kind() + " " + Money.format(line.amountCents()));
        }
        if (lines.isEmpty()) {
            info("(no account needed interest or a fee this month)");
        }
        expectBlocked("bob running month-end processing", () -> accounts.runMonthEnd(bobSession));
    }

    private void passwordsAndSessions() {
        expectBlocked("Someone at alice's unlocked computer changing her password with a wrong current password",
                () -> auth.changePassword(aliceSession, "Not-her-password".toCharArray(),
                        SecureRandomSource.passphrase(), freshCode(alice)));
        expectBlocked("Changing alice's password with her current password but no authenticator code",
                () -> auth.changePassword(aliceSession, alice.password, SecureRandomSource.passphrase(), ""));

        Session oldSession = aliceSession;
        char[] newPassword = SecureRandomSource.passphrase();
        aliceSession = auth.changePassword(aliceSession, alice.password, newPassword, freshCode(alice));
        alice.password = newPassword;
        ok("alice changed her password (current password + fresh authenticator code); her other sessions were signed out");
        expectBlocked("Using alice's old session after the password change", () -> accounts.myAccounts(oldSession));
        ok("alice's new session works: " + accounts.myAccounts(aliceSession).size() + " accounts listed");

        clock.advance(Duration.ofMinutes(11));
        info("(11 minutes pass)");
        expectBlocked("Using alice's session after 11 idle minutes (the limit is 10)", () -> accounts.myAccounts(aliceSession));
    }

    private void auditReview() {
        Session aaronSession = signIn(aaron, BRANCH);
        List<AuditLog.Entry> entries = admin.readAuditLog(aaronSession, 1_000);
        ok("aaron (auditor) read the audit log: " + entries.size() + " entries. The last 25:");
        List<AuditLog.Entry> lastFew = entries.subList(Math.max(0, entries.size() - 25), entries.size());
        for (AuditLog.Entry entry : lastFew) {
            System.out.println("    " + entry.toLine());
        }

        List<String> secrets = new ArrayList<>();
        for (DemoUser person : List.of(adminUser, tina, maria, aaron, alice, bob)) {
            secrets.add(new String(person.password));
        }
        secrets.add(leakedHash);
        secrets.add(aliceSession.token());
        secrets.add(aaronSession.token());
        List<String> lines = entries.stream().map(AuditLog.Entry::toLine).toList();
        check(lines.stream().noneMatch(line -> secrets.stream().anyMatch(line::contains)),
                "No audit entry contains a password, password hash, or session token");
        check(lines.stream().noneMatch(line -> line.contains(aliceChecking) || line.contains(bobChecking)),
                "Account numbers in the audit log are masked to their last four digits");
        expectBlocked("aaron (auditor) deleting entries from the audit log list the bank returned", lastFew::clear);
    }

    // =====================================================================================
    // Helpers for the simulation
    // =====================================================================================

    private DemoUser registerCustomer(Map<String, String> form, String address) {
        // Each simulated customer chooses their own password at runtime; none are in the code.
        char[] password = SecureRandomSource.passphrase();
        AuthService.Enrollment enrollment = auth.registerCustomer(ClientRequest.secure(address), form, password);
        ok(enrollment.username() + " registered and was placed in the " + enrollment.role()
                + " group; the authenticator secret went to their phone");
        return new DemoUser(enrollment.username(), password, new AuthenticatorApp(enrollment.totpSecret(), clock));
    }

    private DemoUser enrollStaff(Session adminSession, String username, String name, Role role) {
        char[] password = SecureRandomSource.passphrase();
        AuthService.Enrollment enrollment = admin.createStaff(adminSession, username, name, role, password);
        ok("admin enrolled " + enrollment.username() + " as " + enrollment.role());
        return new DemoUser(enrollment.username(), password, new AuthenticatorApp(enrollment.totpSecret(), clock));
    }

    private Session signIn(DemoUser person, String address) {
        return auth.login(ClientRequest.secure(address), person.username, person.password, freshCode(person));
    }

    /**
     * Authenticator codes change every 30 seconds and the bank never accepts the same code twice,
     * so the simulation moves the clock to the start of the next 30-second window first.
     */
    private String freshCode(DemoUser person) {
        long secondsIntoStep = Math.floorMod(clock.instant().getEpochSecond(), Totp.STEP_SECONDS);
        clock.advance(Duration.ofSeconds(Totp.STEP_SECONDS - secondsIntoStep));
        return person.phone.currentCode();
    }

    /** A code that is NOT the one on the person's phone right now (what an attacker would type). */
    private static String wrongCode(DemoUser person) {
        int real = Integer.parseInt(person.phone.currentCode());
        return String.format(Locale.ROOT, "%06d", (real + 500_000) % 1_000_000);
    }

    private static void loadSettings(Path file) {
        try {
            BankConfig.load(file);
        } catch (IOException e) {
            throw new IllegalStateException("Settings file could not be read.");
        }
    }

    private void expectBlocked(String attempt, Runnable action) {
        try {
            action.run();
            checksFailed++;
            System.out.println("  [NOT BLOCKED!] " + attempt);
        } catch (BankException | IllegalStateException | UnsupportedOperationException blocked) {
            checksPassed++;
            System.out.println("  [BLOCKED]   " + attempt);
            String reason = blocked.getMessage() != null ? blocked.getMessage()
                    : blocked.getClass().getSimpleName() + " (the list is read-only)";
            System.out.println("              -> " + reason);
        }
    }

    private void check(boolean condition, String description) {
        if (condition) {
            checksPassed++;
            System.out.println("  [CHECKED]   " + description);
        } else {
            checksFailed++;
            System.out.println("  [FAILED!]   " + description);
        }
    }

    private static void ok(String message) {
        System.out.println("  [OK]        " + message);
    }

    private static void info(String message) {
        System.out.println("              " + message);
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("=== " + title + " " + "=".repeat(Math.max(3, 70 - title.length())));
    }
}
