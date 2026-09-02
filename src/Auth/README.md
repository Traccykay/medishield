# `src/Auth/` — Authentication, Authorization & User Management

The heart of MediShield's access control. These classes contain the security logic
that the login and admin pages call into.

| Class | Responsibility | Spec |
|-------|----------------|------|
| `Rbac` | Role definitions, "can role X enter area Y?", "can manage users?", sidebar nav visibility (`canAccessNav`/`navFor`), post-login dashboard routing. | §6, §7, §15 |
| `DoctorPatientAuthorizer` | Executes one joined doctor policy: an active patient assignment **and** exact ownership of the current active `with_doctor` visit. Provides point checks with optional MySQL row locking and a non-clinical list form for dashboards/routes. | §6.4, §7, §15 |
| `UserRepository` | The single gateway to the `users` table. Password, status, and role mutators atomically increment `auth_version` and invalidate unused OTPs. MySQL row locks are gated off for SQLite tests. | §16 |
| `AuthService` | Runs a login attempt + brute-force lockout policy (3 = SUSPICIOUS, 5 = lock 15 min). Unknown, inactive, wrong-password, and locked failures share one external result while retaining precise internal/audit outcomes and comparable verification work. | §9.1 |
| `UserService` | Admin "registration": `createUser()` (with password) and `createPendingUser()` (no password, status `inactive`, for the activation-link flow). Validates input, password policy, unique email. | §9.2 |
| `SessionValidator` | Binds pending MFA and authenticated session payloads to the authoritative account `auth_version`, status, and role; enforces pending-login, idle, and absolute ages with fail-closed timestamp parsing. | §16 |
| `OtpService` / `OtpRepository` | Login **second factor**: issue a 6-char code (stored bcrypt-hashed in `otp_codes`) and conditionally consume it under a transaction/row lock. Expired and exhausted codes are burned. | 2FA |
| `ActivationService` / `ActivationRepository` | Activation/reset tokens are conditionally consumed in the same transaction as the authoritative password/status mutation. Token and user rows use MySQL locking while SQLite follows the portable transaction path. | activation |
| `InitialAdminProvisioner` | Guarded first-admin bootstrap: atomically creates one inactive pending admin, delivers an activation link, rolls back failed delivery, and leaves any existing admin untouched. | §9.2 |

## How they fit together
```
login.php        ->  AuthService->attemptLogin()  ->  UserRepository
                 ->  OtpService->issue()  ->  OtpRepository (+ Mailer)
verify_otp.php   ->  SessionValidator->validatePendingLogin()
                 ->  OtpService->verify() -> login_user()
admin/create_user.php -> UserService->createPendingUser() -> UserRepository
                      -> ActivationService->issueFor()    -> ActivationRepository (+ Mailer)
activate.php     ->  ActivationService->activate() -> UserRepository->activate()
provision-initial-admin.php -> InitialAdminProvisioner -> UserService + ActivationService + Mailer
guard.php (page guard) -> SessionValidator (time + auth_version)
                       -> Rbac::canAccessArea() / Rbac::canAccessNav()
                       -> DoctorPatientAuthorizer (doctor object access)
```

## Testability
- `UserRepository` receives an injected `PDO` and `Clock`, so tests run it against
  in-memory SQLite with a fixed clock.
- `DoctorPatientAuthorizer` receives the shared `PDO`; MySQL-only `FOR UPDATE`
  is enabled only for transactional mutation rechecks and omitted on SQLite.
- `AuthService`, `UserService`, `OtpService`, `ActivationService` and
  `InitialAdminProvisioner` receive their dependencies, so policy logic —
  including OTP expiry, activation single-use, bootstrap idempotency, and
  delivery rollback — is verified end-to-end without a real database server.
