# MediShield Entity Relationship Diagram

This ERD is generated from `sql/schema.sql` and the current migrations. It shows
the core healthcare workflow, authentication/verification tables, and the
tamper-evident audit log used by MediShield.

```mermaid
erDiagram
    USERS {
        int user_id PK
        varchar full_name
        varchar email UK
        varchar password_hash
        enum role
        enum status
        int failed_login_count
        datetime locked_until
        boolean must_change_password
        datetime created_at
        datetime updated_at
    }

    PATIENTS {
        int patient_id PK
        int user_id FK
        varchar patient_number UK
        varchar full_name
        date date_of_birth
        enum gender
        varchar phone
        varchar address
        varchar emergency_contact
        datetime created_at
    }

    PATIENT_ASSIGNMENTS {
        int assignment_id PK
        int patient_id FK
        int staff_user_id FK
        int assigned_by FK
        boolean active
        datetime created_at
    }

    VITALS {
        int vitals_id PK
        int patient_id FK
        int nurse_id FK
        decimal temperature_c
        smallint systolic_mmhg
        smallint diastolic_mmhg
        smallint pulse_bpm
        decimal weight_kg
        text symptoms
        datetime created_at
    }

    MEDICAL_RECORDS {
        int record_id PK
        int patient_id FK
        int doctor_id FK
        text diagnosis_encrypted
        text treatment_encrypted
        datetime created_at
        datetime updated_at
    }

    LAB_REQUESTS {
        int lab_request_id PK
        int patient_id FK
        int record_id FK
        int doctor_id FK
        varchar test_name
        text reason
        enum status
        datetime created_at
    }

    LAB_RESULTS {
        int lab_result_id PK
        int lab_request_id FK,UK
        int patient_id FK
        int lab_technician_id FK
        text result_encrypted
        datetime created_at
    }

    PRESCRIPTIONS {
        int prescription_id PK
        int patient_id FK
        int record_id FK
        int doctor_id FK
        text medication_encrypted
        text dosage_encrypted
        text instructions_encrypted
        enum status
        datetime created_at
    }

    DISPENSING_RECORDS {
        int dispensing_id PK
        int prescription_id FK
        int patient_id FK
        int pharmacist_id FK
        enum status
        text remarks
        datetime created_at
    }

    AUDIT_LOGS {
        int log_id PK
        int user_id
        varchar user_role
        varchar action
        varchar module
        varchar affected_record_id
        varchar ip_address
        text user_agent
        enum status
        enum anomaly_flag
        varchar attempted_identifier
        varchar previous_hash
        varchar current_hash
        datetime created_at
    }

    OTP_CODES {
        int otp_id PK
        int user_id FK
        varchar code_hash
        int attempts
        datetime expires_at
        datetime used_at
        datetime created_at
    }

    ACCOUNT_ACTIVATIONS {
        int activation_id PK
        int user_id FK
        char token_hash UK
        datetime expires_at
        datetime used_at
        datetime created_at
    }

    USERS ||--o| PATIENTS : "may own patient login"
    USERS ||--o{ PATIENT_ASSIGNMENTS : "assigned as staff"
    USERS ||--o{ PATIENT_ASSIGNMENTS : "creates assignment"
    PATIENTS ||--o{ PATIENT_ASSIGNMENTS : "has assignments"

    USERS ||--o{ VITALS : "nurse records"
    PATIENTS ||--o{ VITALS : "has vitals"

    USERS ||--o{ MEDICAL_RECORDS : "doctor writes"
    PATIENTS ||--o{ MEDICAL_RECORDS : "has records"

    USERS ||--o{ LAB_REQUESTS : "doctor orders"
    PATIENTS ||--o{ LAB_REQUESTS : "has lab requests"
    MEDICAL_RECORDS ||--o{ LAB_REQUESTS : "includes requests"

    LAB_REQUESTS ||--o| LAB_RESULTS : "receives result"
    PATIENTS ||--o{ LAB_RESULTS : "has lab results"
    USERS ||--o{ LAB_RESULTS : "lab uploads"

    USERS ||--o{ PRESCRIPTIONS : "doctor issues"
    PATIENTS ||--o{ PRESCRIPTIONS : "has prescriptions"
    MEDICAL_RECORDS ||--o{ PRESCRIPTIONS : "includes prescriptions"

    PRESCRIPTIONS ||--o{ DISPENSING_RECORDS : "is dispensed/refused"
    PATIENTS ||--o{ DISPENSING_RECORDS : "has dispensing history"
    USERS ||--o{ DISPENSING_RECORDS : "pharmacist records"

    USERS ||--o{ OTP_CODES : "receives login OTPs"
    USERS ||--o{ ACCOUNT_ACTIVATIONS : "receives activation links"
    USERS ||--o{ AUDIT_LOGS : "logical actor"
```

## Relationship Notes

- `users` stores all login-capable actors: patients, nurses, doctors, lab staff,
  pharmacists, and admins.
- `patients.user_id` is optional because a patient demographic record can exist
  with or without a patient login account.
- `patient_assignments` controls object-level access by linking patients to
  assigned nurses/doctors and recording the admin who created the assignment.
- Clinical data flows from `patients` into `vitals`, `medical_records`,
  `lab_requests`, `lab_results`, `prescriptions`, and `dispensing_records`.
- Sensitive clinical payloads are encrypted at rest in the encrypted text
  columns for diagnoses, treatments, lab results, medications, dosages, and
  prescription instructions.
- `otp_codes` and `account_activations` store only hashes of verification secrets,
  never plaintext OTPs or activation tokens.
- `audit_logs.user_id` is treated as a logical link to `users`, but the schema
  intentionally does not declare a foreign key so historical forensic logs can
  survive account deletion or changes.
