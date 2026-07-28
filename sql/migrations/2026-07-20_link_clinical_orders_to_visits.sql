-- Link new clinical data and order prices to the consultation that created them.
-- Existing rows remain NULL because no deterministic visit can be inferred safely.
ALTER TABLE medical_records
    ADD COLUMN IF NOT EXISTS visit_id INT UNSIGNED NULL,
    ADD INDEX IF NOT EXISTS idx_mr_visit (visit_id);

ALTER TABLE lab_requests
    ADD COLUMN IF NOT EXISTS visit_id INT UNSIGNED NULL,
    ADD COLUMN IF NOT EXISTS catalog_price_kes INT UNSIGNED NULL,
    ADD INDEX IF NOT EXISTS idx_lr_visit (visit_id);

ALTER TABLE prescriptions
    ADD COLUMN IF NOT EXISTS visit_id INT UNSIGNED NULL,
    ADD COLUMN IF NOT EXISTS catalog_price_kes INT UNSIGNED NULL,
    ADD INDEX IF NOT EXISTS idx_rx_visit (visit_id);

-- MariaDB supports IF NOT EXISTS for columns and indexes but not foreign keys.
-- Check metadata before adding each named constraint so a rerun remains safe.
SET @add_fk_mr_visit = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE medical_records ADD CONSTRAINT fk_mr_visit FOREIGN KEY (visit_id) REFERENCES visits(visit_id)',
        'SELECT 1'
    )
    FROM information_schema.table_constraints
    WHERE constraint_schema = DATABASE()
      AND table_name = 'medical_records'
      AND constraint_name = 'fk_mr_visit'
);
PREPARE add_fk_mr_visit FROM @add_fk_mr_visit;
EXECUTE add_fk_mr_visit;
DEALLOCATE PREPARE add_fk_mr_visit;

SET @add_fk_lr_visit = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE lab_requests ADD CONSTRAINT fk_lr_visit FOREIGN KEY (visit_id) REFERENCES visits(visit_id)',
        'SELECT 1'
    )
    FROM information_schema.table_constraints
    WHERE constraint_schema = DATABASE()
      AND table_name = 'lab_requests'
      AND constraint_name = 'fk_lr_visit'
);
PREPARE add_fk_lr_visit FROM @add_fk_lr_visit;
EXECUTE add_fk_lr_visit;
DEALLOCATE PREPARE add_fk_lr_visit;

SET @add_fk_rx_visit = (
    SELECT IF(COUNT(*) = 0,
        'ALTER TABLE prescriptions ADD CONSTRAINT fk_rx_visit FOREIGN KEY (visit_id) REFERENCES visits(visit_id)',
        'SELECT 1'
    )
    FROM information_schema.table_constraints
    WHERE constraint_schema = DATABASE()
      AND table_name = 'prescriptions'
      AND constraint_name = 'fk_rx_visit'
);
PREPARE add_fk_rx_visit FROM @add_fk_rx_visit;
EXECUTE add_fk_rx_visit;
DEALLOCATE PREPARE add_fk_rx_visit;
