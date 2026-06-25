# `src/Support/` — Cross-cutting Helpers

Small, dependency-free utilities used across the codebase.

| Class | Purpose |
|-------|---------|
| `Clock` | An **injectable** source of the current time (UTC). Lets time-dependent logic (lockout windows, audit timestamps) be tested deterministically by supplying a fixed time. |

Nothing here talks to the database or the network, so these classes are trivially
unit-tested.
