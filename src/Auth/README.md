# `src/Auth/` — Authentication, Authorization & User Management

The heart of MediShield's access control. These classes contain the security logic
that the login and admin pages call into.

| Class | Responsibility | Spec |
|-------|----------------|------|
| `Rbac` | Role definitions, "can role X enter area Y?", "can manage users?", post-login dashboard routing. | §6, §7, §15 |
| `UserRepository` | The single gateway to the `users` table. All queries are PDO prepared statements; SQL is portable (MySQL **and** SQLite). | §16 |
| `AuthService` | Runs a login attempt + brute-force lockout policy (3 = SUSPICIOUS, 5 = lock 15 min). Anti-enumeration via dummy hash + generic errors. | §9.1 |
| `UserService` | Admin "registration": validates input + password policy, enforces unique email, hashes, and creates the user (forces password change on first login). | §9.2 |

## How they fit together
```
login.php        ->  AuthService->attemptLogin()  ->  UserRepository
admin/create_user.php -> UserService->createUser() -> PasswordPolicy + UserRepository
guard.php (page guard) -> Rbac::canAccessArea()
```

## Testability
- `UserRepository` receives an injected `PDO` and `Clock`, so tests run it against
  in-memory SQLite with a fixed clock.
- `AuthService` and `UserService` receive the repository, so their policy logic is
  verified end-to-end without a real database server.
