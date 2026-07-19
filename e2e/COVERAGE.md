# Browser workflow coverage matrix

Every user-facing change must update this matrix and a Playwright scenario in
the same pull request. See the mandatory rule in the test-driven-development
skill.

| Feature area | Current UI coverage | Required follow-up |
| --- | --- | --- |
| OTP sign-in | Covered | Invalid OTP and lockout path |
| Reception, triage, doctor, lab, pharmacy | Covered | Additional validation and retry paths |
| Patient registration contact validation | Covered — Kenyan-format validation and distinct normalized emergency-contact number rejection | Additional browser coverage for optional demographic fields |
| Patient-number generation | Covered — prepopulated locked field and a tampered-number rejection | Exercise the rare database-collision retry with an end-to-end test double if one is introduced |
| Doctor/lab/pharmacy history and pharmacy payment | Covered — an assigned doctor sees rendered vitals, diagnoses, lab results, prescription details, and dispensing outcome after the staff workflow; an unassigned doctor is denied without disclosure | Empty-history states |
| Role denial | One receptionist-to-doctor denial covered | Full role and object-ownership matrix |
| Account activation | Not covered | Create user, consume activation link, and OTP sign-in |
| Change password | Not covered | Forced, voluntary, invalid-current-password, and mismatch paths |
| Administrator reset password | Not covered | Reset email, token consumption, and login with the replacement password |
| Forgot password | Recovery request and account-enumeration protection covered | Consume reset link and verify replacement-password login |
| Administrator user management | Not covered | Create, activate/deactivate, self-protection, and assignment paths |
| Patient self-service | Not covered | Profile, records, labs, prescriptions, and cross-patient denial |
| Reports and payments | Not covered | Verify each non-placeholder user-visible behavior |
