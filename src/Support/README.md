# `src/Support/` — Cross-cutting Helpers

Small, dependency-free utilities used across the codebase.

| Class | Purpose |
|-------|---------|
| `BootstrapConfigValidator` | Fail-closed, dependency-free startup policy: explicit supported mail transport everywhere and complete SMTP plus HTTPS application URL in production, using one constant sanitized diagnostic. |
| `Clock` | An **injectable** source of the current time (UTC). It makes time-dependent logic deterministic and strictly parses canonical database timestamps without PHP's impossible-date normalization. |
| `DisposableDatabase` | Central allowlist that prevents destructive browser-test setup and seed scripts from targeting the normal application database, while allowing setup helpers to use either the configured database or a named disposable target. |

Nothing here talks to the database or the network, so these classes are trivially
unit-tested.
