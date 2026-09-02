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

The runner checks that Node.js, PHP, and MySQL are available. If MySQL/MariaDB
is stopped, its shared `scripts\ensure-mysql.ps1` bootstrap tries a Windows
service, default XAMPP, then Scoop MariaDB and waits for a real SQL connection.
On the first run, it downloads the versions of Playwright and Chromium specified by this project;
later runs reuse them. It then starts a temporary local web server, recreates
only the `medishield_ui_test` database, and seeds role-specific test accounts.
It never changes the normal `medishield_db` database.

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

### Security hostile-path harness (`security-hostile.spec.js`)

This is not a penetration test or a replacement for a code review. It is a
repeatable regression harness for the security properties that are easy to
break during normal feature work. It deliberately tries unsafe paths and
asserts the safe result:

| Hostile path | What the test proves |
| --- | --- |
| Low-privilege role requests an admin page or another patient's record | The server denies access and does not render protected patient data. |
| Administrator revokes a doctor assignment while its visit remains active; the revoked or another doctor retries direct reads and a valid-CSRF mutation | The encounter returns to the existing nurse queue, the revoked doctor becomes selectable again, dashboard/list/detail/history/profile access disappears immediately, protected values remain undisclosed, no forged diagnosis is written, and the denial audit is `BLOCKED` / `HIGH_RISK` with the patient identifier. |
| Authenticated form POST has no CSRF token | The request is rejected and no patient is created. |
| Stored patient value contains HTML markup | The value is rendered as text, not executable DOM. |
| Login request and invalid credentials | Required security headers are sent, `X-Powered-By` is absent, and errors do not reveal whether an account exists. |
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
patient-scoped `BLOCKED` / `HIGH_RISK` denial is stored without submitted
clinical values.

Run every browser test, including the harness, with:

```powershell
.\scripts\run-ui-tests.ps1
```

To iterate on only the hostile-path checks after Node, PHP, and MySQL/MariaDB
are ready, use:

```powershell
npx.cmd playwright test e2e\security-hostile.spec.js
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
