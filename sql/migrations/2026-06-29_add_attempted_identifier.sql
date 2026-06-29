-- ============================================================================
-- Migration: add attempted_identifier to audit_logs
-- Date:      2026-06-29
-- ----------------------------------------------------------------------------
-- WHY: Failed logins must record the email/username that was typed, so an admin
--      can follow up on possibly-leaked credentials — even when the email does
--      not match any account ("who did what"). See sql/schema.sql for the full
--      column comment.
--
-- WHY OUTSIDE THE HASH CHAIN: attempted_identifier is PII. It is intentionally
--      NOT part of the HMAC hash chain so it can be scrubbed (set to NULL) after
--      the retention window without breaking AuditLogger::verifyChain(). The
--      scrub is performed by scripts/purge-audit-pii.php (a privileged
--      maintenance task, never request-path app code).
--
-- IDEMPOTENT: `ADD COLUMN IF NOT EXISTS` (MariaDB) makes this safe to re-run and
--      a no-op on fresh installs where sql/schema.sql already created the column.
--      NOTE: MySQL 8 does not support IF NOT EXISTS on ADD COLUMN — if you run on
--      MySQL 8, drop the `IF NOT EXISTS` and run this only once.
-- ============================================================================

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS attempted_identifier VARCHAR(255) NULL
    AFTER anomaly_flag;
