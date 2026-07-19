# src/Clinical/

Clinical workflow classes live here. They cover the demo flow after patient
assignment:

- nurses record vitals and can route an assigned patient to a doctor
- doctors add encrypted diagnoses/treatments, request lab tests, and issue
  encrypted prescriptions
- lab users work from the request queue and upload encrypted results
- pharmacists work from the prescription queue and record dispensing outcomes

Pages call `ClinicalService` for validation, authorization-sensitive workflow
rules, encryption, and transactions. `ClinicalRepository` owns the PDO prepared
statements.
