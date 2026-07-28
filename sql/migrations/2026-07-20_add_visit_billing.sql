-- Add visit-linked immutable billing records. CREATE TABLE IF NOT EXISTS is
-- idempotent here because these are new tables, not an upgrade of an old shape.
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
