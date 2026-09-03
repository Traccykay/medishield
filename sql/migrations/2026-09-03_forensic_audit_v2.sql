-- Phase 5 forensic hardening.
--
-- Existing audit rows remain format v1 and keep their stored HMACs unchanged.
-- They receive deterministic sequence/event metadata in log_id order. The
-- keyed singleton head is intentionally initialized by
-- scripts/initialize-audit-chain.php after this structural migration.

SET @audit_has_seq = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_logs' AND COLUMN_NAME = 'seq'
);
SET @audit_add_seq = IF(
    @audit_has_seq = 0,
    'ALTER TABLE audit_logs ADD COLUMN seq BIGINT UNSIGNED NULL AFTER log_id',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_add_seq;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

SET @audit_has_event_id = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_logs' AND COLUMN_NAME = 'event_id'
);
SET @audit_add_event_id = IF(
    @audit_has_event_id = 0,
    'ALTER TABLE audit_logs ADD COLUMN event_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER seq',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_add_event_id;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

SET @audit_has_key_id = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_logs' AND COLUMN_NAME = 'key_id'
);
SET @audit_add_key_id = IF(
    @audit_has_key_id = 0,
    'ALTER TABLE audit_logs ADD COLUMN key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER event_id',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_add_key_id;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

SET @audit_has_format = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_logs' AND COLUMN_NAME = 'format_version'
);
SET @audit_add_format = IF(
    @audit_has_format = 0,
    'ALTER TABLE audit_logs ADD COLUMN format_version SMALLINT UNSIGNED NULL AFTER key_id',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_add_format;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

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

-- Once a keyed head exists, a repeated migration must never "repair" sequence
-- or version metadata. Before initialization, each legacy field is backfilled
-- only when every row still has that field uninitialized. Mixed/pre-existing
-- forensic metadata is preserved so constraints or initialization fail closed
-- rather than silently renumbering suspicious rows.
SET @audit_head_initialized = (
    SELECT COUNT(*) FROM audit_chain_head WHERE singleton_id = 1
);
SET @audit_has_assigned_seq = (
    SELECT COUNT(*) FROM audit_logs WHERE seq IS NOT NULL
);
SET @audit_sequence = 0;
SET @audit_backfill_seq = IF(
    @audit_head_initialized = 0 AND @audit_has_assigned_seq = 0,
    'UPDATE audit_logs SET seq = (@audit_sequence := @audit_sequence + 1) ORDER BY log_id',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_backfill_seq;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

SET @audit_has_assigned_event = (
    SELECT COUNT(*) FROM audit_logs WHERE event_id IS NOT NULL AND event_id <> ''
);
SET @audit_backfill_event = IF(
    @audit_head_initialized = 0 AND @audit_has_assigned_event = 0,
    'UPDATE audit_logs SET event_id = CONCAT(''legacy-'', log_id)',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_backfill_event;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

SET @audit_has_assigned_key = (
    SELECT COUNT(*) FROM audit_logs WHERE key_id IS NOT NULL AND key_id <> ''
);
SET @audit_backfill_key = IF(
    @audit_head_initialized = 0 AND @audit_has_assigned_key = 0,
    'UPDATE audit_logs SET key_id = ''legacy-v1''',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_backfill_key;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

SET @audit_has_assigned_format = (
    SELECT COUNT(*) FROM audit_logs WHERE format_version IS NOT NULL AND format_version <> 0
);
SET @audit_backfill_format = IF(
    @audit_head_initialized = 0 AND @audit_has_assigned_format = 0,
    'UPDATE audit_logs SET format_version = 1',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_backfill_format;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

ALTER TABLE audit_logs
    MODIFY seq BIGINT UNSIGNED NOT NULL,
    MODIFY event_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    MODIFY key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    MODIFY format_version SMALLINT UNSIGNED NOT NULL,
    MODIFY previous_hash VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    MODIFY current_hash VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;

SET @audit_has_positive_seq_check = (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'audit_logs'
       AND CONSTRAINT_NAME = 'chk_audit_seq_positive'
       AND CONSTRAINT_TYPE = 'CHECK'
);
SET @audit_add_positive_seq_check = IF(
    @audit_has_positive_seq_check = 0,
    'ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_seq_positive CHECK (seq >= 1)',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_add_positive_seq_check;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

SET @audit_has_uq_seq = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_logs' AND INDEX_NAME = 'uq_audit_seq'
);
SET @audit_add_uq_seq = IF(
    @audit_has_uq_seq = 0,
    'ALTER TABLE audit_logs ADD UNIQUE KEY uq_audit_seq (seq)',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_add_uq_seq;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

SET @audit_has_uq_event = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_logs' AND INDEX_NAME = 'uq_audit_event'
);
SET @audit_add_uq_event = IF(
    @audit_has_uq_event = 0,
    'ALTER TABLE audit_logs ADD UNIQUE KEY uq_audit_event (event_id)',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_add_uq_event;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;

SET @audit_has_uq_previous = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'audit_logs' AND INDEX_NAME = 'uq_audit_previous_hash'
);
SET @audit_add_uq_previous = IF(
    @audit_has_uq_previous = 0,
    'ALTER TABLE audit_logs ADD UNIQUE KEY uq_audit_previous_hash (previous_hash)',
    'SELECT 1'
);
PREPARE audit_stmt FROM @audit_add_uq_previous;
EXECUTE audit_stmt;
DEALLOCATE PREPARE audit_stmt;
