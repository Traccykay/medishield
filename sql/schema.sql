-- =====================================================================
-- MediShield - Database Schema (MySQL / MariaDB - the engine XAMPP ships)
-- =====================================================================
-- Creates all tables for the full system (spec v2 section 10). Deliverable 1
-- actively uses `users`; the remaining tables are created now so later modules
-- (vitals, diagnosis, lab, pharmacy, audit) drop straight in.
--
-- Load with:   scripts\setup-db.ps1
-- or manually: mysql -u root medishield_db < sql\schema.sql
--
-- Conventions (spec section 25):
--   roles    : patient, receptionist, nurse, doctor, lab, pharmacist, admin
--   charset  : utf8mb4 ; all timestamps stored in UTC by the application.
-- =====================================================================

-- Emergency audit actions: EMERGENCY_ACCESS_GRANTED, EMERGENCY_ACCESS_DENIED,
-- EMERGENCY_ACCESS_VIEWED, EMERGENCY_ACCESS_REVIEWED, EMERGENCY_ACCESS_REVOKED.
SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- ---------------------------------------------------------------------
-- users : every account that can log in (staff, admin, patient logins)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id              INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    full_name            VARCHAR(150) NOT NULL,
    email                VARCHAR(150) NOT NULL UNIQUE,
    password_hash        VARCHAR(255) NOT NULL,                 -- bcrypt/argon2, never plaintext
    role                 ENUM('patient','receptionist','nurse','doctor','lab','pharmacist','admin') NOT NULL,
    status               ENUM('active','inactive') NOT NULL DEFAULT 'active',
    failed_login_count   INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until         DATETIME NULL,                          -- account is "locked" while this is in the future
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    auth_version         BIGINT UNSIGNED NOT NULL DEFAULT 1,     -- monotonic credential/status/role epoch
    created_at           DATETIME NOT NULL,
    updated_at           DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- patients : demographic record, optionally linked to a login account
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patients (
    patient_id        INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    user_id           INT UNSIGNED NULL,
    patient_number    VARCHAR(50) NOT NULL UNIQUE,
    full_name         VARCHAR(150) NOT NULL,
    date_of_birth     DATE NOT NULL,
    gender            ENUM('male','female','other') NOT NULL,
    phone             VARCHAR(30) NULL,
    address           VARCHAR(255) NULL,
    emergency_contact VARCHAR(150) NULL,
    created_at        DATETIME NOT NULL,
    CONSTRAINT fk_patient_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- patient_assignments : which nurse/doctor is assigned to which patient
-- (defines "assigned patient" access used by RBAC; spec section 9.3/15)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patient_assignments (
    assignment_id   INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    patient_id      INT UNSIGNED NOT NULL,
    staff_user_id   INT UNSIGNED NOT NULL,
    assigned_by     INT UNSIGNED NOT NULL,
    active          TINYINT(1) NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL,
    CONSTRAINT fk_pa_patient FOREIGN KEY (patient_id)    REFERENCES patients(patient_id) ON DELETE CASCADE,
    CONSTRAINT fk_pa_staff   FOREIGN KEY (staff_user_id) REFERENCES users(user_id)       ON DELETE CASCADE,
    CONSTRAINT fk_pa_admin   FOREIGN KEY (assigned_by)   REFERENCES users(user_id),
    UNIQUE KEY uq_active_assignment (patient_id, staff_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- visits : administrative arrival, payment and care-routing state.
-- Receptionists can create/read these records but never clinical records.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS visits (
    visit_id        INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    patient_id      INT UNSIGNED NOT NULL,
    receptionist_id INT UNSIGNED NOT NULL,
    nurse_id        INT UNSIGNED NULL,
    doctor_id       INT UNSIGNED NULL,
    active_doctor_id INT UNSIGNED NULL,
    payment_method  ENUM('cash','insurance') NOT NULL,
    insurer         VARCHAR(100) NULL,
    status          ENUM('triage','with_nurse','with_doctor','lab','pharmacy','completed') NOT NULL DEFAULT 'triage',
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL,
    CONSTRAINT fk_visit_patient      FOREIGN KEY (patient_id)      REFERENCES patients(patient_id),
    CONSTRAINT fk_visit_receptionist FOREIGN KEY (receptionist_id) REFERENCES users(user_id),
    CONSTRAINT fk_visit_nurse        FOREIGN KEY (nurse_id)        REFERENCES users(user_id),
    CONSTRAINT fk_visit_doctor       FOREIGN KEY (doctor_id)       REFERENCES users(user_id),
    INDEX idx_visit_status (status),
    INDEX idx_visit_doctor_status (doctor_id, status),
    UNIQUE KEY uq_visit_active_doctor (active_doctor_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- billing_bills / billing_charges : immutable visit-linked price snapshots.
-- Charges use integer Kenyan shillings; a bill's total is the sum of line_total.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS billing_bills (
    bill_id           INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    visit_id          INT UNSIGNED NOT NULL UNIQUE,
    patient_id        INT UNSIGNED NOT NULL,
    payment_method    ENUM('cash','insurance') NOT NULL,
    insurer           VARCHAR(100) NULL,
    payment_status    ENUM('unpaid','pending_insurance','paid') NOT NULL DEFAULT 'unpaid',
    payment_reference VARCHAR(100) NULL,
    receipt_number    VARCHAR(100) NULL,
    recorded_by       INT UNSIGNED NULL,
    paid_at           DATETIME NULL,
    created_at        DATETIME NOT NULL,
    updated_at        DATETIME NOT NULL,
    CONSTRAINT fk_bill_visit     FOREIGN KEY (visit_id) REFERENCES visits(visit_id),
    CONSTRAINT fk_bill_patient   FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
    CONSTRAINT fk_bill_recorder  FOREIGN KEY (recorded_by) REFERENCES users(user_id),
    INDEX idx_bill_patient (patient_id),
    INDEX idx_bill_status (payment_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS billing_charges (
    charge_id           INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    bill_id             INT UNSIGNED NOT NULL,
    charge_type         ENUM('service','medication') NOT NULL,
    description_snapshot VARCHAR(150) NOT NULL,
    unit_price_snapshot INT UNSIGNED NOT NULL,
    quantity            INT UNSIGNED NOT NULL,
    line_total          INT UNSIGNED NOT NULL,
    created_at          DATETIME NOT NULL,
    CONSTRAINT fk_charge_bill FOREIGN KEY (bill_id) REFERENCES billing_bills(bill_id),
    INDEX idx_charge_bill (bill_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- vitals : nurse-recorded measurements (validated before AES-256-GCM encryption)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vitals (
    vitals_id       INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    patient_id      INT UNSIGNED NOT NULL,
    nurse_id        INT UNSIGNED NOT NULL,
    temperature_encrypted TEXT NOT NULL,                           -- base64(iv||tag||ciphertext)
    systolic_encrypted    TEXT NOT NULL,
    diastolic_encrypted   TEXT NOT NULL,
    pulse_encrypted       TEXT NOT NULL,
    weight_encrypted      TEXT NOT NULL,
    symptoms_encrypted    TEXT NULL,
    created_at      DATETIME NOT NULL,
    CONSTRAINT fk_vitals_patient FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
    CONSTRAINT fk_vitals_nurse   FOREIGN KEY (nurse_id)   REFERENCES users(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- medical_records : doctor diagnosis + treatment (encrypted at rest)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS medical_records (
    record_id            INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    visit_id             INT UNSIGNED NOT NULL,
    patient_id           INT UNSIGNED NOT NULL,
    doctor_id            INT UNSIGNED NOT NULL,
    diagnosis_encrypted  TEXT NOT NULL,                         -- base64(iv||tag||ciphertext)
    treatment_encrypted  TEXT NULL,
    created_at           DATETIME NOT NULL,
    updated_at           DATETIME NOT NULL,
    CONSTRAINT fk_mr_visit   FOREIGN KEY (visit_id)   REFERENCES visits(visit_id),
    CONSTRAINT fk_mr_patient FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
    CONSTRAINT fk_mr_doctor  FOREIGN KEY (doctor_id)  REFERENCES users(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- lab_requests : tests ordered by a doctor (status tracked here)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lab_requests (
    lab_request_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    visit_id       INT UNSIGNED NOT NULL,
    patient_id     INT UNSIGNED NOT NULL,
    record_id      INT UNSIGNED NOT NULL,
    doctor_id      INT UNSIGNED NOT NULL,
    test_name      VARCHAR(150) NOT NULL,
    reason         TEXT NULL,
    catalog_price_kes INT UNSIGNED NOT NULL,
    status         ENUM('pending','completed') NOT NULL DEFAULT 'pending',
    created_at     DATETIME NOT NULL,
    CONSTRAINT fk_lr_visit   FOREIGN KEY (visit_id)   REFERENCES visits(visit_id),
    CONSTRAINT fk_lr_patient FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
    CONSTRAINT fk_lr_record  FOREIGN KEY (record_id)  REFERENCES medical_records(record_id),
    CONSTRAINT fk_lr_doctor  FOREIGN KEY (doctor_id)  REFERENCES users(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- lab_results : encrypted result payload (one per request)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lab_results (
    lab_result_id     INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    lab_request_id    INT UNSIGNED NOT NULL UNIQUE,
    patient_id        INT UNSIGNED NOT NULL,
    lab_technician_id INT UNSIGNED NOT NULL,
    result_encrypted  TEXT NOT NULL,                            -- base64(iv||tag||ciphertext)
    created_at        DATETIME NOT NULL,
    CONSTRAINT fk_res_request FOREIGN KEY (lab_request_id)    REFERENCES lab_requests(lab_request_id),
    CONSTRAINT fk_res_patient FOREIGN KEY (patient_id)        REFERENCES patients(patient_id),
    CONSTRAINT fk_res_tech    FOREIGN KEY (lab_technician_id) REFERENCES users(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- prescriptions : doctor-issued medication (encrypted at rest)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS prescriptions (
    prescription_id        INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    visit_id               INT UNSIGNED NOT NULL,
    patient_id             INT UNSIGNED NOT NULL,
    record_id              INT UNSIGNED NOT NULL,
    doctor_id              INT UNSIGNED NOT NULL,
    medication_encrypted   TEXT NOT NULL,
    dosage_encrypted       TEXT NOT NULL,
    instructions_encrypted TEXT NULL,
    catalog_price_kes      INT UNSIGNED NOT NULL,
    status                 ENUM('pending','dispensed','refused') NOT NULL DEFAULT 'pending',
    created_at             DATETIME NOT NULL,
    CONSTRAINT fk_rx_visit   FOREIGN KEY (visit_id)   REFERENCES visits(visit_id),
    CONSTRAINT fk_rx_patient FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
    CONSTRAINT fk_rx_record  FOREIGN KEY (record_id)  REFERENCES medical_records(record_id),
    CONSTRAINT fk_rx_doctor  FOREIGN KEY (doctor_id)  REFERENCES users(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- dispensing_records : pharmacist dispensing actions
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispensing_records (
    dispensing_id   INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    prescription_id INT UNSIGNED NOT NULL,
    patient_id      INT UNSIGNED NOT NULL,
    pharmacist_id   INT UNSIGNED NOT NULL,
    status          ENUM('pending','dispensed','refused') NOT NULL DEFAULT 'dispensed',
    remarks         TEXT NULL,
    created_at      DATETIME NOT NULL,
    CONSTRAINT fk_dr_rx      FOREIGN KEY (prescription_id) REFERENCES prescriptions(prescription_id),
    CONSTRAINT fk_dr_patient FOREIGN KEY (patient_id)      REFERENCES patients(patient_id),
    CONSTRAINT fk_dr_pharm   FOREIGN KEY (pharmacist_id)   REFERENCES users(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- audit_logs : append-only, HMAC hash-chained forensic log (spec 9.8)
-- The application DB user is granted only SELECT+INSERT here (no edit/delete).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id             INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    seq                BIGINT UNSIGNED NOT NULL,
    event_id           VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    key_id             VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    format_version     SMALLINT UNSIGNED NOT NULL,
    user_id            INT UNSIGNED NULL,
    user_role          VARCHAR(50) NOT NULL,
    action             VARCHAR(150) NOT NULL,
    module             VARCHAR(100) NOT NULL,
    affected_record_id VARCHAR(100) NULL,
    ip_address         VARCHAR(45) NOT NULL,
    user_agent         TEXT NULL,
    status             ENUM('SUCCESS','FAILED','BLOCKED') NOT NULL,
    anomaly_flag       ENUM('NORMAL','SUSPICIOUS','HIGH_RISK') NOT NULL DEFAULT 'NORMAL',
    -- attempted_identifier: the email/username typed on a failed login. Captured so
    -- an admin can follow up on possibly-leaked credentials (even for unknown users).
    -- This is PII and is DELIBERATELY NOT part of the HMAC hash chain, so it can be
    -- scrubbed (set NULL) after the retention window without breaking verifyChain().
    attempted_identifier VARCHAR(255) NULL,
    previous_hash      VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    current_hash       VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at         DATETIME NOT NULL,
    CONSTRAINT chk_audit_seq_positive CHECK (seq >= 1),
    UNIQUE KEY uq_audit_seq (seq),
    UNIQUE KEY uq_audit_event (event_id),
    UNIQUE KEY uq_audit_previous_hash (previous_hash),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_flag (anomaly_flag),
    INDEX idx_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Keyed commitment to the current audit tip. The singleton row is initialized
-- by scripts/initialize-audit-chain.php because its MAC requires the secret key.
CREATE TABLE IF NOT EXISTS audit_chain_head (
    singleton_id       TINYINT UNSIGNED PRIMARY KEY,
    last_seq           BIGINT UNSIGNED NOT NULL,
    last_log_id        INT UNSIGNED NULL,
    head_hash          VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    key_id             VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    format_version     SMALLINT UNSIGNED NOT NULL,
    key_check          CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    head_mac           CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    updated_at         DATETIME NOT NULL,
    CONSTRAINT chk_audit_chain_head_singleton CHECK (singleton_id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- request_throttles : HMAC-scoped fixed-window budgets for unauthenticated
-- login, OTP, and password-reset requests. Raw client IPs are never stored.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS request_throttles (
    scope_hash        CHAR(64) PRIMARY KEY,
    attempt_count     INT UNSIGNED NOT NULL,
    window_started_at DATETIME NOT NULL,
    INDEX idx_throttle_window (window_started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- otp_codes : one-time passcodes for the second login factor (2FA).
-- After a correct email+password, a short-lived 6-char code is generated,
-- emailed to the user, and must be entered to finish logging in.
-- Only a HASH of the code is stored (never the plaintext), so a database
-- leak does not reveal usable codes. Rows are short-lived and disposable.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS otp_codes (
    otp_id      INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    user_id     INT UNSIGNED NOT NULL,
    code_hash   VARCHAR(255) NOT NULL,                 -- bcrypt hash of the 6-char code
    attempts    INT UNSIGNED NOT NULL DEFAULT 0,       -- wrong tries against this code
    expires_at  DATETIME NOT NULL,                     -- code is invalid after this (UTC)
    used_at     DATETIME NULL,                         -- set once the code is consumed
    created_at  DATETIME NOT NULL,
    INDEX idx_otp_user (user_id),
    INDEX idx_otp_expires (expires_at),
    CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- account_activations : email-verification / activation links for new users.
-- When an admin creates an account it is created INACTIVE with no usable
-- password. A random token is emailed as a link; clicking it lets the user
-- set their own password, which activates the account. Only a SHA-256 hash
-- of the token is stored, so the database never holds a usable link.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS account_activations (
    activation_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    user_id       INT UNSIGNED NOT NULL,
    token_hash    CHAR(64) NOT NULL,                   -- sha256(token) hex
    expires_at    DATETIME NOT NULL,                   -- link is invalid after this (UTC)
    used_at       DATETIME NULL,                       -- set once the link is consumed
    created_at    DATETIME NOT NULL,
    UNIQUE KEY uq_activation_token (token_hash),
    INDEX idx_activation_user (user_id),
    CONSTRAINT fk_activation_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- Temporary read-only emergency grants. Pending rows cannot authorize reads.
CREATE TABLE IF NOT EXISTS emergency_access_grants (
    grant_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    doctor_id INT UNSIGNED NOT NULL,
    patient_id INT UNSIGNED NOT NULL,
    auth_version BIGINT UNSIGNED NOT NULL,
    session_hash CHAR(64) NOT NULL,
    reason_encrypted TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    authorized_at DATETIME NULL,
    revoked_at DATETIME NULL,
    reviewed_at DATETIME NULL,
    reviewed_by INT UNSIGNED NULL,
    INDEX idx_emergency_review (reviewed_at, grant_id),
    CONSTRAINT fk_emergency_doctor FOREIGN KEY (doctor_id) REFERENCES users(user_id),
    CONSTRAINT fk_emergency_patient FOREIGN KEY (patient_id) REFERENCES patients(patient_id),
    CONSTRAINT fk_emergency_reviewer FOREIGN KEY (reviewed_by) REFERENCES users(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
