# src/Clinical/

Clinical workflow classes live here. They cover the demo flow after patient
assignment:

- nurses record vitals and can route an assigned patient to a doctor
- doctors submit an encounter-bound encrypted diagnosis/treatment with multiple
  catalog lab tests and medications in one consultation; the server snapshots
  each catalog price and encrypts prescription details
- lab users work from the request queue and upload encrypted results
- pharmacists work only from encounters currently assigned to pharmacy and record
  dispensed or terminal refused outcomes; a refusal requires a reason and
  atomically returns the linked encounter to its assigned doctor for review

Pages call `ClinicalService` for validation, authorization-sensitive workflow
rules, encryption, catalog validation, and transactions. `ClinicalRepository`
owns the PDO prepared statements. New medical records, lab requests, and
prescriptions always carry their `visit_id`; legacy rows may be NULL only where
an existing database could not safely infer a historical encounter.

Every doctor mutation performs the central joined authorization check before
validation or linked-record lookup, then rechecks it with transaction-scoped
locking before record lookup, encryption, and writing. All doctor mutation lock
paths acquire the visit/assignment rows before an optional medical-record row.
