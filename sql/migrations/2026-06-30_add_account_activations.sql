-- ============================================================================
-- Migration: add account_activations table (email activation links)
-- Date:      2026-06-30
-- ----------------------------------------------------------------------------
-- WHY: New accounts are created INACTIVE with no usable password. A random token
--      is emailed as an activation link; clicking it lets the user set their own
--      password, which activates the account. Only a SHA-256 hash of the token is
--      stored, so the database never holds a usable link.
--
-- IDEMPOTENT: `CREATE TABLE IF NOT EXISTS` makes this safe to re-run and a no-op
--      on fresh installs where sql/schema.sql already created the table.
-- ============================================================================

CREATE TABLE IF NOT EXISTS account_activations (
    activation_id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    user_id       INT UNSIGNED NOT NULL,
    token_hash    CHAR(64) NOT NULL,
    expires_at    DATETIME NOT NULL,
    used_at       DATETIME NULL,
    created_at    DATETIME NOT NULL,
    UNIQUE KEY uq_activation_token (token_hash),
    INDEX idx_activation_user (user_id),
    CONSTRAINT fk_activation_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
