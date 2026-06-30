# `src/Auth/` — Authentication, Authorization & User Management

The heart of MediShield's access control. These classes contain the security logic
that the login and admin pages call into.

| Class | Responsibility | Spec |
|-------|----------------|------|
| `Rbac` | Role definitions, "can role X enter area Y?", "can manage users?", sidebar nav visibility (`canAccessNav`/`navFor`), post-login dashboard routing. | §6, §7, §15 |
| `UserRepository` | The single gateway to the `users` table. All queries are PDO prepared statements; SQL is portable (MySQL **and** SQLite). Includes `activate()` (set password + status) and a `$status` arg on `create()`. | §16 |
| `AuthService` | Runs a login attempt + brute-force lockout policy (3 = SUSPICIOUS, 5 = lock 15 min). Anti-enumeration via dummy hash + generic errors. Password stage only — OTP is layered after it. | §9.1 |
| `UserService` | Admin "registration": `createUser()` (with password) and `createPendingUser()` (no password, status `inactive`, for the activation-link flow). Validates input, password policy, unique email. | §9.2 |
| `OtpService` / `OtpRepository` | Login **second factor**: issue a 6-char code (stored bcrypt-hashed in `otp_codes`), verify it, expire it, and lock it after too many wrong tries. | 2FA |
| `ActivationService` / `ActivationRepository` | **Account-activation links**: mint a high-entropy token (stored SHA-256-hashed in `account_activations`), validate it, and on activation set the user's chosen password + flip status to `active`. Single-use, time-limited. | activation |

## How they fit together
```
login.php        ->  AuthService->attemptLogin()  ->  UserRepository
                 ->  OtpService->issue()  ->  OtpRepository (+ Mailer)
verify_otp.php   ->  OtpService->verify() ->  login_user()
admin/create_user.php -> UserService->createPendingUser() -> UserRepository
                      -> ActivationService->issueFor()    -> ActivationRepository (+ Mailer)
activate.php     ->  ActivationService->activate() -> UserRepository->activate()
guard.php (page guard) -> Rbac::canAccessArea() / Rbac::canAccessNav()
```

## Testability
- `UserRepository` receives an injected `PDO` and `Clock`, so tests run it against
  in-memory SQLite with a fixed clock.
- `AuthService`, `UserService`, `OtpService` and `ActivationService` receive their
  repositories (and a `Clock`), so their policy logic — including OTP expiry and
  activation single-use — is verified end-to-end without a real database server.
