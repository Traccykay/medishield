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
