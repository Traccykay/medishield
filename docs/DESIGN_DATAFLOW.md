# MediShield — Design & Data-Flow (for project defense)

This document explains, in plain language, how data moves through MediShield for the
security-critical flows: **login**, **OTP (two-factor) verification**, **account
activation**, **role-based redirects**, **patient records**, and **forensic audit
logging**. It is written to be read out loud during a defense — each flow is a short
story of "who sends what to whom, and what is checked".

It ends with a **Tradeoffs & Decisions** section explaining *why* each design choice
was made, so the reasoning (not just the result) can be defended.

---

## 1. The big picture

```
 Browser ──HTTP──> public/*.php (thin pages)
                        │  include
                        ▼
                 includes/bootstrap.php   (config, session, security headers,
                        │                   service container: ms_*() helpers)
                        ▼
                 includes/guard.php       (require_login / require_role /
                        │                   require_area / require_nav)
                        ▼
                   src/  classes          (AuthService, OtpService,
                        │                   ActivationService, UserService, Rbac,
                        ▼                   AuditLogger, Crypto, ...)
                  src/.../Repository       (PDO prepared statements)
                        ▼
                   MySQL / MariaDB         (users, otp_codes, account_activations,
                                            audit_logs, ...)
```

**Golden rule:** pages are thin glue. Every decision that matters (is this password
correct? may this role see this page? is this OTP valid?) is made by a tested class
in `src/`, never inline in a page. "Hidden UI is not authorization" — hiding a
sidebar link never replaces a server-side guard.

---

## 2. Login → OTP → fully authenticated session

MediShield uses **two factors**: something you know (password) and something you
have access to (a code emailed to you). Passing the password is **not** enough.

```
1. Browser  ──POST email+password──>  public/login.php
2. login.php ─> ms_auth()->attemptLogin()      (src/Auth/AuthService.php)
       - wrong password / locked / inactive  -> generic "Invalid email or password",
         failed attempt + anomaly flag written to audit_logs, lockout counter++.
       - correct  -> returns the user row. NOTE: login is NOT completed here.
3. login.php ─> ms_otp_service()->issue(userId) (src/Auth/OtpService.php)
       - generates a 6-char code, stores only its bcrypt HASH in otp_codes,
         returns the plaintext code.
4. login.php ─> ms_mailer()->send(... code ...) (LogMailer dev / SmtpMailer prod)
       - audit: OTP_SENT (SUCCESS)
5. login.php  sets  $_SESSION['pending_login'] = {user_id, role}   (NOT auth yet!)
       redirect -> public/verify_otp.php
6. Browser  ──POST code──>  verify_otp.php
7. verify_otp.php ─> ms_otp_service()->verify(userId, code)
       'ok'       -> login_user(user)  (regenerates session id, sets $_SESSION['auth'])
                     audit: OTP_VERIFIED (SUCCESS)  -> redirect to landing page
       'invalid'  -> audit OTP_FAILED  -> "try again"
       'expired'  -> audit OTP_EXPIRED -> back to login (get a new code)
       'too_many' -> audit OTP_FAILED (SUSPICIOUS) -> code killed, restart login
```

Key point for defense: between step 5 and step 7 the user is **not** logged in.
`$_SESSION['pending_login']` only holds a user id for routing; the real
`$_SESSION['auth']` is created only after the OTP is verified, inside `login_user()`,
which also regenerates the session id to prevent session fixation.

---

## 3. Account activation (admin creates user → user sets own password)

The admin never types a password for the new user. The user sets their own password
through a one-time emailed link.

```
1. Admin ──POST name+email+role──>  public/admin/create_user.php  (require_area('admin'))
2. ─> ms_user_service()->createPendingUser()    (src/Auth/UserService.php)
       - inserts the user with status 'inactive' and a SENTINEL password hash
         ('PENDING_ACTIVATION'), which no password can ever verify against.
       - audit: USER_CREATED (SUCCESS)
3. ─> ms_activation_service()->issueFor(userId)  (src/Auth/ActivationService.php)
       - generates a 32-byte random token, stores only its SHA-256 HASH in
         account_activations with an expiry, returns the plaintext token.
4. ─> ms_mailer()->send(... activate.php?token=... ...)
       - audit: ACTIVATION_SENT (SUCCESS)
5. User ──GET activate.php?token=...──>  public/activate.php
       - validate() the token (known? unused? not expired?) -> show "set password" form
6. User ──POST new password+confirm──>  activate.php
       ─> ms_activation_service()->activate(token, password, confirm)
            - re-validates token, enforces PasswordPolicy + confirm match,
            - UserRepository::activate(): sets the real password hash AND status='active',
            - marks the token used (single-use link).
       - audit: ACCOUNT_ACTIVATED (SUCCESS)  -> user can now log in (which triggers OTP)
```

Because the account is `inactive` until activation, `AuthService` refuses to log it
in even if someone guessed a password — **defense in depth**: status check *and*
unverifiable sentinel hash both block a pending account.

---

## 4. Role-based redirects (where you land, what you see)

- After full login, `landing_path_for($role)` (in `guard.php`) sends **admins** to
  `/admin/dashboard.php` and every other role to `/dashboard.php`.
- The **sidebar** (in `includes/layout.php`) is built from
  `Rbac::navFor($role)` — each role only sees links it is allowed.
- That visibility is **not** the security boundary. Each target page enforces access
  server-side:
  - admin pages call `require_area('admin')`,
  - `reports.php` calls `require_nav('reports')`,
  - `payments.php` calls `require_nav('payments')`,
  - `admin/audit.php` calls `require_area('admin')`.
- A user who types a URL they are not allowed to reach is **audited**
  (`UNAUTHORIZED_ACCESS`, status `BLOCKED`) and shown the 403 page.

| Nav item            | Roles that see it (Rbac::NAV_ROLES)                |
| ------------------- | -------------------------------------------------- |
| Dashboard / Logout  | all roles                                          |
| Users               | admin                                              |
| Reports             | admin, nurse, doctor, lab, pharmacist (not patient)|
| Payments            | admin, pharmacist, patient                         |
| Forensic Auditing   | admin                                              |

---

## 5. Patient records (planned data flow)

Deliverable 1 builds authentication, the admin/user-management slice, and the
security plumbing (OTP, activation, audit). The clinical record flows are specified
and will reuse the exact same plumbing:

```
Doctor/Nurse/Patient ─> require_login()/require_area()
   ─> a (future) RecordService validates the request and RBAC record-ownership
        ("is this patient assigned to me?", "is this the patient's own record?")
   ─> Repository reads/writes via PDO prepared statements
   ─> sensitive fields encrypted at rest with Crypto (AES-256-GCM)
   ─> every read/write audited (PATIENT_VIEW, VITALS_RECORDED, DIAGNOSIS_ADDED, ...)
```

The point to defend: records are never reached without a guard, never queried with
string-concatenated SQL, sensitive fields are encrypted, and every access is logged.

---

## 6. Forensic audit logging (the tamper-evident record)

Every security-relevant event is appended to `audit_logs` via `ms_audit_log()`
(`includes/bootstrap.php` → `src/Audit/AuditLogger.php`).

- Each row is **HMAC-chained** to the previous row (`src/Security/AuditChain.php`):
  changing or deleting any row breaks the chain, which the admin's **integrity
  check** (`verifyChain()`, shown on `admin/audit.php`) detects.
- The log is **append-only in practice**: there is no code path that updates or
  deletes an audit row — even an admin cannot tamper with it.
- Failed logins record the **typed email** (`attempted_identifier`) as PII so an
  admin can follow up on possible credential theft; that PII is later scrubbed by
  `scripts/purge-audit-pii.php` after the retention window, while the row + hash
  chain remain.
- The **Forensic Auditing** page (`admin/audit.php`) is the dedicated viewer; opening
  it is itself audited (`AUDIT_LOGS_VIEWED`).

New audit actions added in this deliverable: `OTP_SENT`, `OTP_VERIFIED`,
`OTP_FAILED`, `OTP_EXPIRED`, `ACTIVATION_SENT`, `ACCOUNT_ACTIVATED`.

---

## 7. Files changed / added in this deliverable

**New source classes**
- `src/Mail/Mailer.php`, `LogMailer.php`, `SmtpMailer.php` — pluggable mail transport.
- `src/Auth/OtpService.php`, `OtpRepository.php` — login second factor.
- `src/Auth/ActivationService.php`, `ActivationRepository.php` — activation links.

**Changed source classes**
- `src/Auth/UserRepository.php` — `create()` gains a `$status`; new `activate()`.
- `src/Auth/UserService.php` — new `createPendingUser()` + sentinel constant.
- `src/Auth/Rbac.php` — sidebar nav map: `canAccessNav()` / `navFor()`.

**Wiring / config**
- `includes/bootstrap.php` — `ms_mailer()`, `ms_otp_service()`, `ms_activation_service()`.
- `includes/guard.php` — new `require_nav()`.
- `includes/layout.php` — app shell: `layout_app_header()` + sidebar + `layout_app_footer()`.
- `config/config.sample.php` — `mail`, `otp`, `activation` settings.
- `public/assets/css/style.css` — app-shell + sidebar styles.

**Pages**
- New: `public/verify_otp.php`, `public/activate.php`, `public/reports.php`,
  `public/payments.php`, `public/admin/audit.php`.
- Changed: `public/login.php` (issue OTP), `public/admin/create_user.php`
  (activation flow), `public/admin/dashboard.php` (table moved to audit page),
  `public/admin/users.php`, `public/dashboard.php` (app layout).

**SQL**
- `sql/schema.sql` + two idempotent migrations for `otp_codes` and
  `account_activations`; `sql/seed.sql` superadmin email is now gmail-style.

**Tests**
- `tests/Integration/OtpServiceTest.php`, `ActivationServiceTest.php`, plus new
  `UserServiceTest` / `RbacTest` cases; `tests/Unit/LogMailerTest.php`;
  `tests/Support/FakeMailer.php`.

---

## 8. How to test each new feature

Dev email uses the **log transport**: instead of sending real email, each message is
written to `logs/mail/*.txt`. Read the OTP/activation link from there.

1. **Apply DB changes** (keeps your data): `scripts\setup-db.ps1` (idempotent), or
   apply the two files in `sql/migrations/` directly.
2. **Run the test suite:** `php vendor\bin\phpunit` — expect all green (88+ tests).
3. **OTP login:**
   - Open `/login.php`, sign in as the superadmin.
   - Open the newest file in `logs/mail/` to get the code.
   - Enter it on `/verify_otp.php` → you reach the dashboard. (First login also
     forces a password change.)
   - Try a wrong code to see `OTP_FAILED`; wait past 10 min to see `OTP_EXPIRED`.
4. **Account activation:**
   - As admin, `/admin/create_user.php` → create a user (no password field).
   - Open the newest `logs/mail/` file → click/copy the `activate.php?token=...` link.
   - Set a password on `/activate.php` → account becomes active → log in with OTP.
5. **Sidebar / RBAC:** log in as different roles and confirm the sidebar items match
   the table in §4; type a disallowed URL (e.g. a patient opening `/reports.php`) and
   confirm you get the 403 page and an `UNAUTHORIZED_ACCESS` audit row.
6. **Forensic auditing:** open `/admin/audit.php` and confirm the new OTP/activation
   events appear and the chain integrity shows **OK**.

---

## 9. Tradeoffs & Decisions (the "why", for learning)

> This section is intentionally educational: it records the alternatives considered
> and why each decision was made, so the design can be defended, not just described.

**OTP stored as a bcrypt hash, not plaintext.**
A 6-character code is low entropy, so we used `password_hash()` (bcrypt) — slow by
design, which makes offline guessing of a leaked code row expensive. *Tradeoff:* we
cannot look a code up by value, so we fetch the newest unused row for the user and
`password_verify()` against it. We accept that small cost for "a DB leak never
reveals a usable code".

**Activation token hashed with SHA-256, not bcrypt.**
The token is 32 random bytes (~256 bits) — brute force is infeasible regardless of
hash speed. SHA-256 is deterministic, so we can look the row up by hash directly.
*Tradeoff / lesson:* hash choice depends on the *entropy of the secret* — slow bcrypt
for low-entropy human input (passwords, OTPs), fast SHA-256 for high-entropy random
tokens. Using bcrypt here would force a slow table scan for no security gain.

**OTP layered in the page after AuthService, not inside it.**
`AuthService` still owns password + lockout (unchanged, still tested). The OTP step
lives in `login.php`/`verify_otp.php`. *Tradeoff:* the login flow spans two pages and
a `pending_login` session value, which is slightly more moving parts — but it keeps
each class single-purpose and let us add 2FA without touching the lockout logic.

**Activation-link sets the password (no admin-chosen password).**
Alternative was the admin typing a temporary password the user changes at first
login. We chose activation links because the admin never knows the user's password,
and there is no temporary secret to leak or transmit out-of-band. *Tradeoff:* it
needs working email (or the dev log transport) and an extra table — worth it for the
stronger property.

**Sentinel password hash + `inactive` status for pending accounts (defense in depth).**
Either one alone would block login, but we use both: the status check (in
`AuthService`) and an unverifiable hash. If one guard were ever bypassed by a bug,
the other still holds. *Tradeoff:* a tiny bit of redundancy for a meaningful safety
margin.

**Pluggable Mailer (`LogMailer` dev / `SmtpMailer` prod), chosen by config.**
Lets the whole OTP/activation flow be demonstrated and graded on a laptop with no
email account, while production sends real mail — same calling code. *Tradeoff:* one
extra interface, but it also makes the flows testable with a `FakeMailer` and keeps
credentials in config (never hardcoded).

**Sidebar visibility in `Rbac`, labels/URLs in the layout; pages still guard.**
We split "who may see a nav item" (authorization, in `Rbac`) from "how it renders"
(presentation, in `layout.php`), and we never treat hiding a link as security — every
page re-checks with `require_nav`/`require_area`. *Tradeoff:* the rule lives in two
files, but each file has one job and the security boundary stays on the server.

**Audit log is append-only and HMAC-chained.**
We deliberately provide no update/delete path for audit rows and chain each row to the
last, so tampering is *evident* even though we cannot make it *impossible* on a box
where someone has DB access. *Tradeoff:* we cannot edit a mistaken row — which is
exactly the property a forensic log should have.
