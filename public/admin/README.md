# `public/admin/` — Administrator Area

Pages here are restricted to the **admin** role. Each one calls
`require_area('admin')` first, which enforces authentication, session timeout,
the forced-password-change redirect, **and** that the user's role may enter the
admin area. Any blocked attempt is audited (`UNAUTHORIZED_ACCESS`, status
`BLOCKED`) and the user is sent to `/unauthorized.php`.

This area implements the administrator capabilities from the specification:
create users, assign roles, activate/deactivate accounts, and monitor security
activity. It is the **only** way accounts are created — MediShield has no public
self-registration.

## Pages

| File | Purpose | Audit actions |
|------|---------|---------------|
| `dashboard.php` | Admin home + security monitor: recent audit events, failed-login / anomaly counts, and audit-chain integrity status. **Read-only** over the audit log. | — |
| `create_user.php` | The "registration" form: create an account and assign one of the six roles. New users start with `must_change_password = 1`. | `USER_CREATED` |
| `users.php` | List all users; activate/deactivate accounts (POST + CSRF only). An admin cannot deactivate their own account. | `USER_UPDATED` |

## Why these guards matter

- **Server-side authorization.** The admin links are hidden from other roles, but
  hiding UI is not security — `require_area('admin')` is what actually stops a
  nurse from POSTing to `create_user.php`.
- **State changes are POST + CSRF.** Activating/deactivating a user is never a
  GET link, so it cannot be triggered by a crafted URL, image tag, or prefetch.
- **The audit log is append-only.** Even an admin can only *read* it here
  (`AuditLogger::recent()`); there is no code path that edits or deletes entries.
