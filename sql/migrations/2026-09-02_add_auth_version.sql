-- Monotonic authentication epoch used to revoke pending MFA and authenticated
-- sessions after a password, status, or role transition.
SET @medishield_auth_version_exists = (
    SELECT COUNT(*)
      FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'users'
       AND COLUMN_NAME = 'auth_version'
);

SET @medishield_auth_version_migration = IF(
    @medishield_auth_version_exists = 0,
    'ALTER TABLE users ADD COLUMN auth_version BIGINT UNSIGNED NOT NULL DEFAULT 1 AFTER must_change_password',
    'SELECT 1'
);

PREPARE medishield_auth_version_statement FROM @medishield_auth_version_migration;
EXECUTE medishield_auth_version_statement;
DEALLOCATE PREPARE medishield_auth_version_statement;
