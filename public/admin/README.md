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
| `dashboard.php` | Admin home + security monitor: recent audit events, failed-event / anomaly counts, local audit-chain integrity, and a separate external rollback-anchor status. Expected anchor-freshness limitations remain normal evidence and do not inflate these counters. **Read-only** over the audit log. | — |
| `audit.php` | Paginated forensic audit viewer (25 verified events per page). Quarantines rows unless local verification passes; records definite failures as high risk, verification errors as suspicious, and expected missing/stale-anchor states as normal operational evidence. | `AUDIT_LOGS_VIEWED`, `INTEGRITY_VERIFIED` |
| `create_user.php` | The "registration" form: create an account and assign one of the seven roles. New users start with `must_change_password = 1`. | `USER_CREATED` |
| `users.php` | List all users; activate/deactivate accounts (POST + CSRF only). An admin cannot deactivate their own account. | `USER_UPDATED` |
| `assign_patient.php` | Assign/unassign patients to nurses and doctors. Doctor unassignment immediately revokes access and transactionally returns a matching active consultation to its existing nurse queue; nurse unassignment remains assignment-only. | `ASSIGNMENT_CHANGED` |

## Why these guards matter

- **Server-side authorization.** The admin links are hidden from other roles, but
  hiding UI is not security — `require_area('admin')` is what actually stops a
  nurse from POSTing to `create_user.php`.
- **State changes are POST + CSRF.** Activating/deactivating a user is never a
  GET link, so it cannot be triggered by a crafted URL, image tag, or prefetch.
- **The audit log is append-only.** Even an admin can only *read* it here
  (`AuditLogger::page()`); there is no code path that edits or deletes entries.
