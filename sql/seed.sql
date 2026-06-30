-- =====================================================================
-- MediShield - Seed Data
-- =====================================================================
-- Creates the bootstrap "superadmin" account. This is the ONLY user that
-- exists out of the box; the superadmin then registers every other user via
-- the admin pages (spec: admins create users, there is no public sign-up).
--
-- Login (CHANGE IMMEDIATELY after first login):
--   email    : medishield.superadmin@gmail.com
--   password : ChangeMe!2026
--
-- must_change_password = 1 forces a password change on first login.
-- The password_hash below is a bcrypt hash of the password above.
-- Re-generate your own with:
--   php -r "echo password_hash('YourNewPassword', PASSWORD_DEFAULT);"
--
-- INSERT IGNORE makes this script safe to run more than once (email is UNIQUE).
-- =====================================================================

INSERT IGNORE INTO users
    (full_name, email, password_hash, role, status,
     failed_login_count, locked_until, must_change_password, created_at, updated_at)
VALUES
    ('Super Administrator',
     'medishield.superadmin@gmail.com',
     '$2y$12$pNrBEkehOVvfp2GXMwMYP.he90heHfKoOxzoVLazmBfIRm4vA2qry',
     'admin',
     'active',
     0,
     NULL,
     1,
     UTC_TIMESTAMP(),
     UTC_TIMESTAMP());
