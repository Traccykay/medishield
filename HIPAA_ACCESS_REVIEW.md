# HIPAA access-control benchmark review

Reviewed 2026-09-16 for the academic project. This is a source-code review and
technical improvement record, not a HIPAA compliance determination or a complete
risk analysis. No real patient information was needed for this review.

## Who can see what

| Role | Current application boundary | Matters needing policy review |
| --- | --- | --- |
| Patient | Own linked demographics, records, lab results, prescriptions and bills | Portal access is not a complete records-request or personal-representative process. |
| Receptionist | Patient demographics, intake and authorized billing workflow; no clinical chart routes | Billing line items can themselves reveal health information; document necessary fields and purposes. |
| Nurse | Assigned patient demographics and vitals; triage workflow | Assignment lifetime needs an explicit operational policy. Recent authored vitals now also require a current assignment. |
| Doctor | Active assignment AND ownership of the current active `with_doctor` visit; clinical history and encounter actions | Follow-up and emergency workflows need explicit policies; do not bypass revocation to implement them. |
| Lab | Department pending requests, request-specific result upload and department completed-test history | Completed history is department-wide, not restricted to the technician who performed a test. Justify scope and retention or introduce narrower authorization. |
| Pharmacist | Pending prescriptions for pharmacy-stage encounters, dispensing actions and department dispensed history | All pharmacists can view department dispensed medication history. Define a legitimate job purpose and history scope. |
| Admin | Users, assignments, demographics, billing supervision and audit/security information | No automatic clinical-area access. Account/role and assignment management are powerful indirect privileges requiring oversight. |

These are application boundaries, not database-operator or workstation access
controls. People holding database credentials, encryption keys, backups or host
administrator privileges require separate controls.

## Confirmed gap addressed

`ClinicalRepository::recentVitalsByNurse()` previously filtered only by author.
The nurse dashboard could decrypt and display a patient's historic vital signs
after that nurse's assignment was revoked, despite the direct vitals page denying
access. It now additionally requires an active matching patient assignment in
the database query. The regression test verifies visibility before revocation,
denial afterwards and preservation of the underlying clinical record.

The nurse dashboard and vitals-history page now submit `PATIENT_VIEW` audit
events using patient identifiers, without copying clinical values into audit
rows. Dashboard events are deduplicated per patient per request.

## Remaining work before any stronger compliance claim

1. Approve a written access matrix covering purpose, fields, patient scope,
   department history, assignment expiry, temporary coverage and emergency access.
   A shared department queue can be legitimate; role-wide history requires a
   documented need and is not automatically a HIPAA violation.
2. Inventory every PHI read, including lists, dashboards, billing and histories,
   and verify audit coverage and review procedures. The nursing additions do not
   establish complete application-wide read auditing. Review audit-write failure
   handling and operational alerting as well as chain integrity.
3. Define and test emergency access procedures. This review does not add a
   universal administrator override or establish an emergency workflow.
4. Establish workforce onboarding, access approval, periodic access reviews,
   termination procedures, training and sanctions. Test account revocation and
   assignment revocation across existing sessions and all read surfaces.
5. Evaluate the actual deployment: HTTPS, host and database privileges, key
   custody, backups/restoration, physical access and incident/breach response.
   Assess business-associate agreements where applicable and patient-rights
   procedures. Code alone does not establish these safeguards.

## Evidence and limitations

Validation: the new revocation regression failed before the query change and
passed afterwards (4 assertions). The full PHP suite completed with 434 tests,
1,944 assertions, 4 skipped tests and no failures on PHP 8.5.7 / PHPUnit 12.5.30.
The two edited nursing pages passed PHP syntax checks. Browser verification
could not start because required npm/MySQL commands were unavailable on PATH.
The installed PHPUnit differs from the repository's pinned 10.5 line; a locked
Composer restore was attempted but stopped during slow dependency fetching.
PHP 8.1 / pinned PHPUnit and browser validation remain outstanding.

Relevant implementation includes `src/Auth/Rbac.php`,
`src/Auth/DoctorPatientAuthorizer.php`, `src/Patient/PatientService.php`,
`includes/guard.php`, `src/Clinical/ClinicalRepository.php`, and the role-specific
routes under `public/`. Existing tests cover patient ownership, doctor encounter
authorization, session revocation and clinical workflows.

The authoritative specification referenced by AGENTS.md,
`../MediShield_Specification_v2.md`, was absent and was not found beneath
`D:/xampp/htdocs`. This review therefore used the supplied AGENTS.md, README and
available implementation; specification conformance remains unverified.

## Official benchmark references

- [HHS: minimum necessary](https://www.hhs.gov/hipaa/for-professionals/faq/minimum-necessary/index.html)
  explains limiting workforce access according to role and need.
- [HHS: treatment, payment and operations](https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/disclosures-treatment-payment-health-care-operations/index.html)
  distinguishes workforce access policies from the exception for disclosures to,
  or requests by, healthcare providers for treatment. HIPAA does not prescribe
  MediShield's particular seven-role matrix.
- [HHS: Security Rule summary](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html)
  describes administrative, physical and technical safeguards.
- [HHS: audit protocol](https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol/index.html)
  provides evaluation criteria for access management and information-system review.
