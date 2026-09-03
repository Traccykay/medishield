# `public/` — Web Root (Document Root)

This directory is the **only** part of the application a browser may reach
directly. The web server (XAMPP/Apache, or `php -S ... -t public`) must point its
document root **here**, so that `src/`, `includes/`, `config/`, `sql/` and
`vendor/` stay outside the web root and can never be requested over HTTP.

The repository-root `.htaccess` is defense in depth for an existing XAMPP
`htdocs\medishield\public` subfolder arrangement. It denies every sibling of
`public`; this directory's own `.htaccess` denies non-allowlisted assets,
documentation, the development router, and include-only partials. That fallback
is not equivalent to a verified dedicated public web root until it has been
exercised under Apache with `mod_rewrite`, `mod_headers`, and overrides enabled.

Every page is intentionally **thin glue**: it includes `../includes/guard.php`
(authentication, session timeout, role checks) and, when it renders HTML,
`../includes/layout.php`. All real logic lives in `src/` so it can be unit-tested
without a web server.

## Pages

| File | Purpose | Access |
|------|---------|--------|
| `index.php` | Entry point; routes the visitor to login or their landing page. | Public |
| `login.php` | Login form + authentication. Audits LOGIN_SUCCESS/LOGIN_FAILED. | Public |
| `logout.php` | POST-only session termination; audits LOGOUT. | Authenticated |
| `change_password.php` | Set a new password (also the forced first-login change). Audits PASSWORD_RESET. | Authenticated |
| `dashboard.php` | Generic landing page for non-admin roles in Deliverable 1. | Authenticated |
| `patients.php` | Patient workspace: admin searches all demographics, nurses/doctors see assigned patients, patients are routed to their own profile. | Authenticated + role/object checks |
| `patient_profile.php` | Patient demographic profile guarded by ownership/assignment/admin checks. Audits PATIENT_VIEW. | Authenticated + object check |
| `register_patient.php` | Patient registration form for admin, nurse, and doctor. Audits PATIENT_REGISTERED. | Admin, nurse, doctor |
| `unauthorized.php` | 403 page shown when a role is denied an area. | Authenticated |
| `admin/` | Administrator user-management + security monitoring. | Admin only |
| `nurse/` | Nurse dashboard, vitals recording/history, and doctor routing for assigned patients. | Nurse only |
| `doctor/` | Doctor dashboard, patient review, encrypted diagnosis, lab requests, and prescriptions. | Doctor only |
| `lab/` | Lab request queue and encrypted result upload. | Lab only |
| `pharmacy/` | Prescription queue and dispensing/refusal workflow. | Pharmacist only |
| `patient/` | Patient self-service dashboard, own profile, records, lab results, and prescriptions. | Patient only |
| `assets/css/style.css` | The only currently allowlisted static asset. | Public |

## Conventions enforced on every page

- **Guard first.** A protected page calls `require_login()`, `require_role()` or
  `require_area()` *before* reading or writing anything. Hidden UI is never a
  substitute for a server-side check.
- **One request boundary on every form controller.**
  `request_post_guard($module)` permits GET rendering, accepts only verified
  POST mutations, and rejects every other method. Action-only controllers pass
  `postOnly: true`. A missing, wrong, or array-shaped token receives the same
  generic 403 response and exactly one `CSRF_REJECTED` audit attempt before any
  field parsing, object lookup, or domain work.
- **Array-safe request parsing.** Controllers use `request_positive_int()` and
  `request_string()` after the request guard, so malformed arrays cannot become
  object ID 1 or trigger a PHP type error.
- **Escape every output** with `e()` (HTML-escaping) — defence against XSS.
- **Build internal links/redirects with `ms_url('/path')`** (and let `redirect()`
  handle base paths) — never hardcode `/login.php`. Both helpers require a
  local target beginning with exactly one slash and reject absolute,
  scheme-relative, control-character, malformed, encoded-separator, and
  traversal-shaped values. Successful POST handlers use 303 See Other.
- **Audit security events** with `ms_audit_log([...])`; a failed audit write is
  logged internally and never lets a rejected request reach domain mutation.
- **No secrets or stack traces** are sent to the browser (see `bootstrap.php`).

## Serving locally

```powershell
# From the repo root, after config/config.php and the database exist:
php -S 127.0.0.1:8000 -t public public/router.php
# then browse http://127.0.0.1:8000/
```

`router.php` is only for PHP's development server. It never delegates a request
back to PHP's permissive default file/script handling: it executes only its
enumerated route files, serves only `assets/css/style.css` with
`text/css; charset=utf-8`, and owns controlled 403/404 responses. All receive
the core security headers and `Referrer-Policy: no-referrer`; dynamic and error
responses are private/no-store while the stylesheet is cacheable. Apache denies
direct requests for `router.php`.

When adding a page or static asset, update `PublicRuntimePolicy` and its unit,
subprocess, and browser coverage in the same change. A file merely existing
under `public/` is not enough to make the development router expose it.
