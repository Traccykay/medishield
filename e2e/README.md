# Browser UI tests and live demonstration

This folder contains automated browser tests. Think of each test as a scripted
hospital staff member: it opens MediShield, signs in, fills forms, clicks
buttons, and verifies the next screen is correct. This catches broken user
flows before a person discovers them manually.

Start with the [root README](../README.md) if you have not yet cloned or set up
MediShield. It explains Git, XAMPP, PHP, Node.js, and the initial database
setup. The instructions below begin after that one-time setup is complete.

## Before you run anything

1. Open the **XAMPP Control Panel** and start **MySQL**. It must be green.
2. Open PowerShell in the repository folder. For example:

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

The runner checks that Node.js, PHP, and MySQL are available. On the first run,
it downloads the versions of Playwright and Chromium specified by this project;
later runs reuse them. It then starts a temporary local web server, recreates
only the `medishield_ui_test` database, and seeds role-specific test accounts.
It never changes the normal `medishield_db` database.

Wait for the command to finish. `3 passed` means every scripted workflow
completed. Any other result means a check failed; see **When a test fails**.

## Run a supervisor demonstration

For a visible, no-manual-login walkthrough, run:

```powershell
.\scripts\run-ui-tests.ps1 -Demo
```

Demo mode opens Chromium, slows every interaction by 650 ms, and records each
successful scenario to `test-results/`. Do not interact with the browser while
the scripted walkthrough is running. The application window closes when the
walkthrough finishes; play the recorded videos afterward if needed.

## What the tests prove

The suite covers OTP sign-in, RBAC denial, Kenyan contact validation, patient
registration/search, triage/vitals, doctor assignment, diagnosis, lab routing
and result return, prescription pricing, and pharmacy dispensing.

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
