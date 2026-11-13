/**
 * IT 355 Group Project 2
 * Authors: Srida Kalidindi, Allaya Foster, Serena Sah, Valerie Fernandes, Karsten Tisdale
 * Secure Bank Program Showcasing CWEs
 * Filename: BankConfig.java
 *
 * Bank settings with secure defaults, allowed ranges, and loading from a secret-free settings file.
 */

package securebank;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.TreeSet;

/**
 * The bank's tunable settings.
 */
final class BankConfig {

    // CWE-1188 (Initialization of Resource with an Insecure Default): every setting starts at a
    // safe value, so the bank is secure even with no settings file at all. Each setting also has a
    // hard minimum and maximum, so a settings file can tune the bank but can't make it unsafe
    // (for example, sessions can't last longer than 30 minutes and lockout can't be set to 1,000
    // tries). Two-factor sign-in and TLS aren't settings at all: they're always on, so there's
    // nothing to forget to switch on. There is also no default administrator password; see
    // AuthService.bootstrapAdministrator().
    enum Setting {
        SESSION_TIMEOUT_MINUTES("session.timeoutMinutes", 15, 5, 30, true),
        MAX_FAILED_LOGINS_PER_ACCOUNT("auth.maxFailedLoginsPerAccount", 5, 3, 10, false),
        MAX_FAILED_LOGINS_PER_ADDRESS("auth.maxFailedLoginsPerAddress", 3, 3, 50, false),
        ADDRESS_BLOCK_MINUTES("auth.addressBlockMinutes", 30, 5, 1_440, false),
        TELLER_CASH_LIMIT_DOLLARS("teller.cashLimitDollars", 5_000, 100, 10_000, true),
        SAVINGS_INTEREST_BASIS_POINTS("savings.monthlyInterestBasisPoints", 25, 0, 100, false),
        CHECKING_MINIMUM_BALANCE_DOLLARS("checking.minimumBalanceDollars", 500, 0, 5_000, false),
        CHECKING_MONTHLY_FEE_CENTS("checking.monthlyFeeCents", 500, 0, 2_500, false);

        final String key;
        final int defaultValue;
        final int min;
        final int max;
        /** Whether an administrator may change this while the bank is running. */
        final boolean runtimeEditable;

        Setting(String key, int defaultValue, int min, int max, boolean runtimeEditable) {
            this.key = key;
            this.defaultValue = defaultValue;
            this.min = min;
            this.max = max;
            this.runtimeEditable = runtimeEditable;
        }

        static Optional<Setting> forKey(String key) {
            for (Setting setting : values()) {
                if (setting.key.equals(key)) {
                    return Optional.of(setting);
                }
            }
            return Optional.empty();
        }
    }

    private static final List<String> SECRET_WORDS = List.of(
            "password", "passwd", "secret", "token", "credential", "apikey", "api_key",
            "privatekey", "private_key", "pepper");

    // CWE-366 (listed in our report as CWE-336, Race Condition within a Thread): EnumMap isn't
    // thread-safe and settings can change while requests are running, so every read and write
    // goes through methods synchronized on this object.
    private final EnumMap<Setting, Integer> values = new EnumMap<>(Setting.class);

    private BankConfig() {
        for (Setting setting : Setting.values()) {
            values.put(setting, setting.defaultValue);
        }
    }

    static BankConfig secureDefaults() {
        return new BankConfig();
    }

    static BankConfig load(Path file) throws IOException {
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        BankConfig config = new BankConfig();
        for (String key : new TreeSet<>(properties.stringPropertyNames())) {
            // CWE-260 (Password in Configuration File): settings files are often copied, emailed,
            // and committed to Git, so they must never hold secrets. If a key even looks like a
            // password, key, or token, the bank refuses to start instead of reading it.
            String lowerKey = key.toLowerCase(Locale.ROOT);
            if (SECRET_WORDS.stream().anyMatch(lowerKey::contains)) {
                throw new BankException.InvalidInput("Settings file must not contain secrets (found '"
                        + key + "'). Provide secrets through the environment instead.");
            }
            // CWE-15 (External Control of System or Configuration Setting): only settings the bank
            // knows about are accepted. Anything else, such as an attempt to add
            // "auth.mfaRequired=false", stops startup instead of being silently ignored.
            Setting setting = Setting.forKey(key).orElseThrow(() ->
                    new BankException.InvalidInput("Unknown setting '" + key + "' in settings file."));
            config.values.put(setting, parse(setting, properties.getProperty(key)));
        }
        return config;
    }

    synchronized int get(Setting setting) {
        return values.get(setting);
    }

    /**
     * Applies a change requested while the bank is running. AdminService checks who is asking;
     * this method checks that the setting may change at runtime and that the value is in range.
     */
    synchronized void applyRuntimeChange(Setting setting, String rawValue) {
        if (!setting.runtimeEditable) {
            throw new BankException.AccessDenied("'" + setting.key + "' cannot be changed while the bank is running.");
        }
        values.put(setting, parse(setting, rawValue));
    }

    synchronized Map<Setting, Integer> snapshot() {
        // CWE-375: callers get a read-only copy, not our live map.
        return Collections.unmodifiableMap(new EnumMap<>(values));
    }

    private static int parse(Setting setting, String rawValue) {
        int value;
        try {
            value = Integer.parseInt(rawValue == null ? "" : rawValue.strip());
        } catch (NumberFormatException notANumber) {
            // CWE-431 (Missing Handler): a bad number becomes a clear error, not a crash.
            throw new BankException.InvalidInput("'" + setting.key + "' must be a whole number.");
        }
        if (value < setting.min || value > setting.max) {
            throw new BankException.InvalidInput("'" + setting.key + "' must be between "
                    + setting.min + " and " + setting.max + ".");
        }
        return value;
    }
}
