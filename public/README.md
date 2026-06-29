# `public/` — Web Root (Document Root)

This directory is the **only** part of the application a browser may reach
directly. The web server (XAMPP/Apache, or `php -S ... -t public`) must point its
document root **here**, so that `src/`, `includes/`, `config/`, `sql/` and
`vendor/` stay outside the web root and can never be requested over HTTP.

Every page is intentionally **thin glue**: it includes `../includes/guard.php`
(authentication, session timeout, role checks) and, when it renders HTML,
`../includes/layout.php`. All real logic lives in `src/` so it can be unit-tested
without a web server.

## Pages

| File | Purpose | Access |
|------|---------|--------|
| `index.php` | Entry point; routes the visitor to login or their landing page. | Public |
| `login.php` | Login form + authentication. Audits LOGIN_SUCCESS/LOGIN_FAILED. | Public |
| `logout.php` | Ends the session; audits LOGOUT. | Authenticated |
| `change_password.php` | Set a new password (also the forced first-login change). Audits PASSWORD_RESET. | Authenticated |
| `dashboard.php` | Generic landing page for non-admin roles in Deliverable 1. | Authenticated |
| `unauthorized.php` | 403 page shown when a role is denied an area. | Authenticated |
| `admin/` | Administrator user-management + security monitoring. | Admin only |
| `assets/` | Static CSS (and future JS/images). | Public |

## Conventions enforced on every page

- **Guard first.** A protected page calls `require_login()`, `require_role()` or
  `require_area()` *before* reading or writing anything. Hidden UI is never a
  substitute for a server-side check.
- **CSRF on every POST.** `Csrf::check($_SESSION, $_POST[Csrf::FIELD])` runs
  before any state change; failures are audited as `CSRF_REJECTED`.
- **Escape every output** with `e()` (HTML-escaping) — defence against XSS.
- **Build internal links/redirects with `ms_url('/path')`** (and let `redirect()`
  handle base paths) — never hardcode `/login.php`. This makes the app work both
  at the web root and under a sub-folder like `http://localhost/medishield/public/`,
  so CSS and links don't 404 when copied into XAMPP's `htdocs`.
- **Audit security events** with `ms_audit_log([...])`; it never crashes the page.
- **No secrets or stack traces** are sent to the browser (see `bootstrap.php`).

## Serving locally

```powershell
# From the repo root, after config/config.php and the database exist:
php -S 127.0.0.1:8000 -t public
# then browse http://127.0.0.1:8000/
```
