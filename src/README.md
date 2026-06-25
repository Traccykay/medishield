# `src/` — Application Logic (PSR-4: `MediShield\`)

All reusable, **unit-testable** business logic lives here. Web pages in `public/`
are intentionally thin — they wire HTTP requests to these classes. Keeping logic
out of the pages is what makes Test-Driven Development possible.

Autoloading: `composer.json` maps namespace `MediShield\` → `src/` (PSR-4), so
`MediShield\Security\PasswordPolicy` resolves to `src/Security/PasswordPolicy.php`.

## Sub-packages
| Namespace | Folder | Responsibility |
|-----------|--------|----------------|
| `MediShield\Support` | `Support/` | Small cross-cutting helpers (e.g. a testable `Clock`). |
| `MediShield\Database` | `Database/` | PDO connection factory. |
| `MediShield\Security` | `Security/` | Password policy, CSRF, AES-256-GCM crypto, audit hash-chain. |
| `MediShield\Auth` | `Auth/` | RBAC, user repository, authentication + user-management services. |

## Design rules (see `AGENTS.md`)
- One class per file; `declare(strict_types=1)` at the top.
- Anything that touches the database receives an injected `PDO` (never creates its
  own), so tests can pass an in-memory SQLite connection.
- No `echo`/HTML here — that belongs in `public/`.
