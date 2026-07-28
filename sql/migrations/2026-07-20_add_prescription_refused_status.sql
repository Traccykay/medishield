-- A refusal is a terminal prescription outcome. Preserve current pending and
-- dispensed rows while allowing the application to record the refusal rather
-- than returning the order to the pharmacy queue.
SET @has_refused_prescription_status = (
    SELECT COUNT(*)
      FROM information_schema.columns
     WHERE table_schema = DATABASE()
       AND table_name = 'prescriptions'
       AND column_name = 'status'
       AND column_type LIKE '%''refused''%'
);
SET @add_refused_prescription_status_sql = IF(
    @has_refused_prescription_status = 0,
    'ALTER TABLE prescriptions MODIFY COLUMN status ENUM(''pending'',''dispensed'',''refused'') NOT NULL DEFAULT ''pending''',
    'SELECT 1'
);
PREPARE add_refused_prescription_status FROM @add_refused_prescription_status_sql;
EXECUTE add_refused_prescription_status;
DEALLOCATE PREPARE add_refused_prescription_status;
