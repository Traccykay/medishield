# `includes/` — Per-request Bootstrap & Shared Glue

These files are included by the thin pages in `public/`. They turn a raw PHP
request into a configured, secured application context **before** any page logic
runs. Pages should `require` `bootstrap.php` first and nothing else from here
directly (it pulls in the rest).

| File | Responsibility |
|------|----------------|
| `bootstrap.php` | The single entry point every page includes first. Loads the Composer autoloader, loads config (`config/config.php`, falling back to `config.sample.php`), forces UTC, installs an error handler that logs to `logs/app_errors.log` (no stack traces to the browser), hardens + starts the session (HttpOnly / SameSite=Strict / Secure-on-HTTPS), sends security headers, and exposes the lazy **service container** (`ms_db()`, `ms_auth()`, `ms_user_service()`, `ms_audit()`, `ms_crypto()`, ...) plus view helpers (`e()`, `redirect()`, `ms_audit_log()`). |
| `headers.php` | Sends the HTTP security headers applied to every response (X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS on HTTPS). Centralised so no page can forget them. |

## Conventions

- Pages must **never** instantiate repositories/services directly — ask the
  container (`ms_auth()`, etc.) so construction stays in one audited place.
- Always escape output with `e()` and always write audit entries with
  `ms_audit_log()` (it auto-attaches IP / user-agent and never crashes the page).
- `guard.php` (authentication/authorization helpers: `require_login()`,
  `require_role()`, session-timeout enforcement, `current_user()`, `logout()`)
  will live here too and is included by every protected page.
