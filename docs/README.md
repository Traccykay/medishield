# docs/

Project documentation that is not tied to a single source directory.

| File | What it covers |
| ---- | -------------- |
| `DESIGN_DATAFLOW.md` | Plain-language data-flow walkthrough of the security-critical features (login, OTP verification, account activation, role-based redirects, patient records, forensic audit logging), the list of files changed per feature, how to test each one, and an educational **Tradeoffs & Decisions** section explaining *why* each design choice was made. Written to be usable during a project defense. |
| `ERD.md` | Mermaid entity relationship diagram generated from `sql/schema.sql`, including healthcare workflow tables, OTP/account activation tables, audit logging, foreign-key relationships, and security notes for encrypted/hash-only fields. |

Per-directory README convention: every collection of files in this repo has a README
describing what it is for, so a new engineer or agent can orient quickly. Code-level
documentation lives as doc comments in the source files themselves.
