-- Add least-privilege reception access and the administrative visit queue.
-- MODIFY is idempotent because the target ENUM definition is fixed.
ALTER TABLE users
    MODIFY role ENUM('patient','receptionist','nurse','doctor','lab','pharmacist','admin') NOT NULL;

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

ALTER TABLE visits
    ADD COLUMN IF NOT EXISTS active_doctor_id INT UNSIGNED NULL,
    ADD UNIQUE INDEX IF NOT EXISTS uq_visit_active_doctor (active_doctor_id);
