# public/nurse/

Nurse-only workflow pages. Nurses see assigned patients, record typed/range
validated vitals, review prior vitals, and route an assigned patient to a doctor.
Every page calls `require_area('nurse')`; patient-specific actions also rely on
the patient assignment checks in `PatientService` / `ClinicalService`.
