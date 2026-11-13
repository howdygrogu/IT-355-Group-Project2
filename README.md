# IT-355 Group Project 2: SecureBank

SecureBank is a small online-banking back end written in Java to show how to avoid the
30 CWEs covered in our report. It has customers, tellers, a manager, an auditor, and an administrator. People sign in with a password plus an authenticator, open accounts, move money, download statements, and import payroll batches batches. At the end of the month the bank adds interest and charges fees, and every security-relevant event goes into an audit log.

Running the program plays out a scripted "day at the bank". Ordinary banking works, and every attack in the script, such as password guessing, forged headers, reading someone else's account, path manipulation, is blocked. The program checks this itself, printing a summary and exiting with status 1 if any attack was not blocked.

The code contains comments for each CWE that's covered, indicating where the CWE would appear if it was not properly avoided.

## CWE to file index

This is a list of files that showcase each CWE so you can easily find them. Ctrl+F in the code and search CWE- in the corresponding file to find where the CWE is showcased.

| CWE | Name | Main location |
|---|---|---|
| 15 | External Control of System or Configuration Setting | `AdminService.changeSetting`, `BankConfig.load` |
| 134 | Use of Externally-Controlled Format String | `StatementService.render`, `AuditLog.Entry.toLine` |
| 256 | Plaintext Storage of a Password | `PasswordHasher` |
| 257 | Storing Passwords in a Recoverable Format | `PasswordHasher` |
| 260 | Password in Configuration File | `BankConfig.load`, `KeyVault`, `config/securebank.properties` |
| 261 | Weak Encoding for Password | `PasswordHasher` |
| 267 | Privilege Defined With Unsafe Actions | `Role`, `Permission` |
| 270 | Privilege Context Switching Error | `PrivilegeContext.runElevated`, `AccountService.withManagerApproval` |
| 272 | Least Privilege Violation | `KeyVault.seal`, `AuthService.bootstrapAdministrator` |
| 283 | Unverified Ownership | `AccountService.accessible` |
| 289 | Authentication Bypass by Alternate Name | `Validation.canonicalUsername`, `StatementService.readStatement` |
| 308 | Use of Single-factor Authentication | `Totp`, `User.checkCredentials` |
| 331 | Insufficient Entropy | `SecureRandomSource` |
| 348 | Use of Less Trusted Source | `ClientRequest`, `AuthService.login` |
| 366 | Race Condition within a Thread | `Account`, `AuthService`, `User`, `UserDirectory`, `PrivilegeContext` |
| 375 | Returning a Mutable Object to an Untrusted Caller | `Account.history`, `AccountSummary`, `PasswordHasher.StoredPassword` |
| 378 | Creation of Temporary File With Insecure Permissions | `SecureFiles`, `StatementService.exportStatement` |
| 413 | Improper Resource Locking | `Account`, `AccountService.transfer` |
| 431 | Missing Handler | `Main.main`, `BatchImporter.importPayroll`, exhaustive `switch` expressions |
| 502 | Deserialization of Untrusted Data | `BatchImporter`, `Main.installDeserializationFilter` |
| 620 | Unverified Password Change | `AuthService.changePassword` |
| 625 | Permissive Regular Expression | `Validation`, `BatchImporter` |
| 778 | Insufficient Logging | `AuditLog` |
| 779 | Logging of Excessive Data | `AuditLog` |
| 798 | Use of Hard-Coded Credentials | `KeyVault.fromEnvironment` |
| 836 | Use of Password Hash Instead of Password for Authentication | `PasswordHasher.verify` |
| 842 | Placement of User into Incorrect Group | `AuthService.registerCustomer`, `AdminService.createStaff` |
| 1062 | Parent Class with References to Child Class | `Account`, `CheckingAccount`, `SavingsAccount` |
| 1095 | Loop Condition Value Update within the Loop | `Totp.match`, `BatchImporter.importPayroll`, `AccountService.runMonthEnd` |
| 1188 | Initialization of Resource with an Insecure Default | `BankConfig`, `AuthService.bootstrapAdministrator` |
