# src/Patient/

Patient-management domain logic lives here. These classes implement the spec
section 9.3 backbone that later clinical modules depend on:

- server-generated, collision-safe patient numbers plus demographic registration and search;
  registration requires a distinct emergency-contact Kenyan mobile number after
  normalizing `0`, `254`, and `+254` representations
- optional linkage between a patient record and a patient login account
- nurse/doctor assignment management through `patient_assignments`
- object-level access decisions for patient profile views

Pages should call `PatientService` for validation and authorization decisions and
`PatientRepository` for read/write persistence. All SQL uses PDO prepared
statements so user-controlled search/profile identifiers are never concatenated
into queries.
