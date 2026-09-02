# `includes/` — Per-request Bootstrap & Shared Glue

These files are included by the thin pages in `public/`. They turn a raw PHP
request into a configured, secured application context **before** any page logic
runs. Pages should `require` `bootstrap.php` first and nothing else from here
directly (it pulls in the rest).

| File | Responsibility |
|------|----------------|
| `error_boundary.php` | Dependency-free failure boundary loaded before Composer or configuration. Suppresses scalar arguments in exception traces, disables browser error display, logs useful diagnostics server-side, clears partial output, and returns a fixed generic 500 response for uncaught exceptions and fatal shutdown errors. |
| `bootstrap.php` | The single entry point every page includes first. Installs the early error boundary, loads Composer and config, forces UTC, hardens + starts the session (HttpOnly / SameSite=Strict / Secure-on-HTTPS), sends security headers, and exposes the lazy **service container** (`ms_db()`, `ms_auth()`, `ms_user_service()`, `ms_audit()`, `ms_crypto()`, ...) plus view helpers (`e()`, `redirect()`, `ms_audit_log()`). |
| `headers.php` | Sends the HTTP security headers applied to every response (X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS on HTTPS). Centralised so no page can forget them. |
| `guard.php` | Server-side authentication & authorization for every protected page. Maps the session to the current user (`current_user()`, `is_logged_in()`), establishes/destroys sessions (`login_user()` regenerates the id to defeat fixation, `logout_user()`), enforces idle + absolute session **timeouts** (`enforce_timeouts()`), and provides the page **guards** `require_login()`, `require_role()` and `require_area()`. Denials are audited (`UNAUTHORIZED_ACCESS` / `BLOCKED`) via `deny_access()` and routed to `/unauthorized.php`. `landing_path_for()` decides where a user lands after login. |
| `layout.php` | Shared HTML shell so every page renders the same hardened, escaped markup: `layout_header($title, $user)`, `layout_footer()`, and `layout_alert($type, $message)`. All values are escaped with `e()`. |
| `partials/` | Include-only escaped view fragments kept outside the HTTP document root. |

## Conventions

- Pages must **never** instantiate repositories/services directly — ask the
  container (`ms_auth()`, etc.) so construction stays in one audited place.
- Always escape output with `e()` and always write audit entries with
  `ms_audit_log()` (it auto-attaches IP / user-agent and never crashes the page).
- Every protected page calls a `guard.php` guard (`require_login()`,
  `require_role()` or `require_area()`) **before** reading or mutating anything —
  hiding UI is never a substitute for a server-side authorization check.
