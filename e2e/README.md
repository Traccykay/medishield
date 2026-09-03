# Browser UI tests and live demonstration

This folder contains automated browser tests. Think of each test as a scripted
hospital staff member or attacker: it opens MediShield, signs in (where
appropriate), sends a request, and verifies the visible result and protected
side effect. This catches broken user flows and security regressions at the
real HTTP/rendering boundary.

Start with the [root README](../README.md) if you have not yet cloned or set up
MediShield. It explains Git, XAMPP, PHP, Node.js, and the initial database
setup. The instructions below begin after that one-time setup is complete.

## Before you run anything

1. Open PowerShell in the repository folder. For example:

   ```powershell
   cd $HOME\Documents\medishield
   ```

3. Confirm Node.js is available:

   ```powershell
   node --version
   ```

   If this reports that `node` is not recognized, install Node.js LTS from
   <https://nodejs.org/>, open a new PowerShell window, and try again.

## Run the regression checks

Run the reusable Windows runner:

```powershell
.\scripts\run-ui-tests.ps1
```

The runner checks that Node.js, PHP, and MySQL are available. It always runs
`npm ci --ignore-scripts` from the official registry with strict SSL, rejects
custom Playwright download-host overrides, and invokes the repository-local
Playwright command. If MySQL/MariaDB
is stopped, its shared `scripts\ensure-mysql.ps1` bootstrap tries a Windows
service, default XAMPP, then Scoop MariaDB and waits for a real SQL connection.
On the first run, it downloads the exact Playwright and Chromium versions specified by this project;
later browser downloads may be reused, while npm dependencies are cleanly
reconciled every time. It then starts a temporary local web server, recreates
only the `medishield_ui_test` database, and seeds deterministic role-specific
test accounts, including the forced-password fixture used by account tests.
Those credentials live only in the CLI-guarded test seeder, whose database
allowlist excludes `medishield_db`; normal setup contains no default account.

Wait for the command to finish. Every listed test must pass. Any failure means
a workflow or security check failed; see **When a test fails**.

## Run a supervisor demonstration

For a visible, no-manual-login walkthrough, run:

```powershell
.\scripts\run-ui-tests.ps1 -Demo
```

Demo mode opens Chromium, slows every interaction by 650 ms, and records each
successful scenario to `test-results/`. Do not interact with the browser while
the scripted walkthrough is running. The application window closes when the
walkthrough finishes; play the recorded videos afterward if needed.

## Suites and what they prove

### Workflow regression (`reception-triage.spec.js`)

This suite covers OTP sign-in, Kenyan contact validation, patient
registration/search, triage/vitals, doctor assignment, diagnosis, lab routing
and result return, prescription pricing, pharmacy dispensing/refusal with
doctor review, an RBAC denial, and account-enumeration-safe password-recovery
messaging.

### Security hostile-path harness (`security-hostile.spec.js` and `request-boundary.spec.js`)

This is not a penetration test or a replacement for a code review. It is a
repeatable regression harness for the security properties that are easy to
break during normal feature work. It deliberately tries unsafe paths and
asserts the safe result:

| Hostile path | What the test proves |
| --- | --- |
| Low-privilege role requests an admin page or another patient's record | The server denies access and does not render protected patient data. |
| Administrator revokes a doctor assignment while its visit remains active; the revoked or another doctor retries direct reads and a valid-CSRF mutation | The encounter returns to the existing nurse queue, the revoked doctor becomes selectable again, dashboard/list/detail/history/profile access disappears immediately, protected values remain undisclosed, no forged diagnosis is written, and the denial audit is `BLOCKED` / `HIGH_RISK` with the patient identifier. |
| Authenticated form POST has no CSRF token | The request is rejected and no patient is created. |
| Every state-changing controller receives missing, wrong, and array-shaped CSRF tokens | All 21 mutation controllers return the same generic 403, write exactly one safe `CSRF_REJECTED` / `BLOCKED` / `SUSPICIOUS` event, and leave every non-audit table unchanged. |
| Object identifiers are submitted as arrays with a valid CSRF token | The request fails closed without a 500 response, array-to-ID-1 coercion, or domain mutation. |
| Read-route identifiers/search values are submitted as arrays | Vitals access fails closed and list/search routes remain scalar-safe without PHP diagnostics. |
| Logout or administrator reset is requested with GET | Both action-only routes return 405; rendered logout navigation remains usable through a tokenized POST form. |
| A valid logout POST completes | The response is 303 See Other with a local path, and the ended session cannot reopen the protected page. |
| Stored patient value contains HTML markup | The value is rendered as text, not executable DOM. |
| Runtime file, directory, traversal, and missing-route probes | Only enumerated PHP routes and the stylesheet are exposed; controlled 403/404 responses carry core headers without diagnostics or directory listings. |
| Login request, stylesheet, and invalid credentials | Dynamic responses have unique security/private-no-store headers, the CSS MIME/cache policy permits the stylesheet to apply in Chromium, attacker-chosen and URL session IDs are ignored, and account failures do not reveal state. |
| Account changes between factors or during a session | Pending MFA and authenticated sessions are revoked after a deactivate/reactivate cycle, cannot regain access, and write a safe blocked audit event. |
| Repeated password-reset submissions from one address | The server throttles the request storm and does not send more reset mail after blocking it. |

`dashboard-kpis.spec.js` also proves that doctor detail/history navigation emits
exactly one safe `PATIENT_VIEW` event per authorized page load, without placing
clinical contents in the audit view, and that doctor dashboard/report pending
order counts remain scoped to the authenticated doctor after queue routing.

`doctor-routing-failure.spec.js` uses a trigger only in the disposable test
database to revoke a doctor assignment immediately after a standalone or
consultation-linked lab/prescription insert. It proves the committed clinical
write remains, routing does not occur, the user sees a message that distinguishes
the saved consultation/orders from the failed routing step, and exactly one
patient-scoped `WORKFLOW_ROUTING_FAILED` / `FAILED` / `SUSPICIOUS` event is
stored without submitted clinical values. Account, workflow, and billing tests
also assert post-MFA `LOGIN_SUCCESS`, actual activation role, one event per
consolidated order, billing mutation/read coverage, and absence of clinical or
payment-reference values from audit rows.

Run every browser test, including the harness, with:

```powershell
.\scripts\run-ui-tests.ps1
```

To iterate on only the hostile-path checks after Node, PHP, and MySQL/MariaDB
are ready, use:

```powershell
.\node_modules\.bin\playwright.cmd test request-boundary security-hostile
```

The complete feature-to-test inventory is in [COVERAGE.md](COVERAGE.md).
Features marked as not covered are known gaps, not proof of coverage; they must
receive a Playwright scenario when implemented or changed.

For the complementary OWASP ZAP passive baseline, reports, and safe active-scan
limits, read [`../SECURITY_TESTING.md`](../SECURITY_TESTING.md).

## When a test fails

1. Read the final red error in PowerShell. It identifies the affected scenario.
2. Open `test-results` in File Explorer. Failed scenarios include a screenshot,
   video, and trace file.
3. To replay a trace, run:

   ```powershell
   npm run show:ui-trace
   ```

4. Ensure MySQL is still running and run the command one more time. The test
   database is recreated each time, so a retry starts from clean test data.
5. If it still fails, share the error and the matching `test-results` folder
   with the engineer fixing the change. Do not edit the test database manually.
