# `includes/` — Per-request Bootstrap & Shared Glue

These files are included by the thin pages in `public/`. They turn a raw PHP
request into a configured, secured application context **before** any page logic
runs. Pages should `require` `bootstrap.php` first and nothing else from here
directly (it pulls in the rest).

| File | Responsibility |
|------|----------------|
| `error_boundary.php` | Dependency-free failure boundary loaded before Composer or configuration. Suppresses scalar arguments in exception traces, disables browser error display, logs useful diagnostics server-side, clears partial output, and returns a fixed generic 500 response with feasible dependency-free security/private-cache headers. |
| `bootstrap.php` | The single entry point every page includes first. Installs the early error boundary, loads Composer and config, routes diagnostics, validates the production mail/HTTPS boundary before sessions or services, hardens + starts the session (HttpOnly / SameSite=Strict / Secure-on-HTTPS), sends security headers plus central private/no-store policy for every dynamic response, and exposes the lazy **service container** and view helpers. |
| `headers.php` | Sends the response policy: `Referrer-Policy: no-referrer`, framing/MIME/CSP/permissions/cross-origin controls, HSTS only on a confirmed HTTPS dynamic request, and private/no-store helpers. Static Apache HSTS belongs in the exercised TLS vhost. |
| `guard.php` | Server-side authentication, authorization, request-attack, and CSRF boundary for protected pages. Maps the session to the current user, establishes/destroys sessions, enforces the five-minute idle + absolute timeouts, and provides the page guards. Denials and high-confidence SQL-injection/XSS-shaped POSTs are blocked and audited at the original URL. |
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
- `ms_url()` and `redirect()` accept only validated local, single-leading-slash
  targets. Redirects use an explicit redirect status; incoming POST defaults to
  303 so a client cannot resubmit the mutation to the destination.
