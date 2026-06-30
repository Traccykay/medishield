-- ============================================================================
-- Migration: add otp_codes table (login second factor / 2FA)
-- Date:      2026-06-30
-- ----------------------------------------------------------------------------
-- WHY: After a correct email+password, MediShield now issues a short-lived
--      6-character one-time passcode (OTP) that the user must enter to finish
--      logging in. Only a bcrypt HASH of the code is stored, never the plaintext.
--
-- IDEMPOTENT: `CREATE TABLE IF NOT EXISTS` makes this safe to re-run and a no-op
--      on fresh installs where sql/schema.sql already created the table.
-- ============================================================================

CREATE TABLE IF NOT EXISTS otp_codes (
    otp_id      INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    user_id     INT UNSIGNED NOT NULL,
    code_hash   VARCHAR(255) NOT NULL,
    attempts    INT UNSIGNED NOT NULL DEFAULT 0,
    expires_at  DATETIME NOT NULL,
    used_at     DATETIME NULL,
    created_at  DATETIME NOT NULL,
    INDEX idx_otp_user (user_id),
    INDEX idx_otp_expires (expires_at),
    CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
