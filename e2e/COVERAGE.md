# Browser workflow coverage matrix

Every user-facing change must update this matrix and a Playwright scenario in
the same pull request. See the mandatory rule in the test-driven-development
skill.

| Feature area | Current UI coverage | Required follow-up |
| --- | --- | --- |
| OTP sign-in | Covered — activated, reset, forced-password, and seed accounts complete the email OTP UI path; unit/integration coverage validates expiry, replay rejection, attempt limits, and IP-scoped request throttling | Invalid OTP and lockout browser path |
| Reception, triage, doctor, lab, pharmacy | Covered — a doctor submits two catalog lab tests and two catalog prescriptions in one consultation; queue transitions wait for every linked order, and a pharmacist refusal returns the encounter to its assigned doctor with visible refusal remarks | Additional validation and retry paths |
| Patient registration contact validation | Covered — Kenyan-format validation and distinct normalized emergency-contact number rejection | Additional browser coverage for optional demographic fields |
| Patient-number generation | Covered — prepopulated locked field and a tampered-number rejection | Exercise the rare database-collision retry with an end-to-end test double if one is introduced |
| Doctor/lab/pharmacy history and pharmacy payment | Covered — an assigned doctor sees rendered vitals, diagnoses, lab results, prescription details, and dispensing outcome after the staff workflow; an unassigned doctor is denied without disclosure | Empty-history states |
| Role denial | One receptionist-to-doctor denial covered | Full role and object-ownership matrix |
| Account activation | Covered — administrator creates a pending user; activation validates mismatch and password policy failures, consumes the emailed token, and signs in through OTP | Expired-token path |
| Change password | Covered — forced and voluntary changes, mismatch, incorrect-current-password, weak-password, unchanged-password, and replacement-password login | CSRF failure path |
| Administrator reset password | Covered — reset email token consumption and OTP login with the replacement password | Expired-token path |
| Forgot password | Recovery request and account-enumeration protection covered; hostile browser flow proves IP-scoped request throttling blocks follow-on reset mail | Consume reset link and verify replacement-password login |
| Administrator user management | Covered — create, activate, deactivate/reactivate, password-reset, and UI/server self-deactivation protection | Assignment paths |
| Patient self-service | Covered — linked profile, records, labs, prescriptions, dashboard counts, and direct cross-patient ownership denial | Empty self-service data states |
| Reports | Not covered | Verify each non-placeholder user-visible behavior |
| Visit billing and payments | Covered — receptionist adds server-priced service charges, records cash receipt and pending insurance claim states, and a linked patient sees only their own paid bill; a forged patient mutation is rejected without changing the total | Insurance settlement and administrator view |
| OWASP ZAP passive baseline | Covered — `scripts/run-zap-baseline.ps1` rebuilds the disposable UI database, starts the local app, and produces HTML/JSON/XML passive-scan reports; `npm run test:zap` is a shortcut | Authenticated ZAP scan only after explicit written authorization and a disposable target scope |
