<?php

declare(strict_types=1);

namespace MediShield\Tests\Support;

use PDO;

/**
 * TestSchema
 * ----------
 * Helper for integration tests. Spins up a throwaway in-memory SQLite database
 * and creates a `users` table whose columns match the production MySQL schema
 * (sql/schema.sql). Because UserRepository uses portable SQL, the exact same
 * repository code runs here as against MySQL/MariaDB — no MySQL server required to
 * test.
 *
 * Each call returns a brand-new, empty database, keeping tests isolated.
 */
final class TestSchema
{
    /**
     * SQLite-compatible mirror of the production `users` table.
     * Types are simplified (TEXT/INTEGER) but column names match exactly.
     */
    private const USERS_DDL = <<<SQL
        CREATE TABLE users (
            user_id              INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name            TEXT    NOT NULL,
            email                TEXT    NOT NULL UNIQUE,
            password_hash        TEXT    NOT NULL,
            role                 TEXT    NOT NULL,
            status               TEXT    NOT NULL DEFAULT 'active',
            failed_login_count   INTEGER NOT NULL DEFAULT 0,
            locked_until         TEXT    NULL,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at           TEXT    NOT NULL,
            updated_at           TEXT    NOT NULL
        );
    SQL;

    /**
     * SQLite-compatible mirror of the production `audit_logs` table.
     * Used to test the hash-chain writer/verifier without a MySQL server.
     */
    private const AUDIT_LOGS_DDL = <<<SQL
        CREATE TABLE audit_logs (
            log_id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id            INTEGER NULL,
            user_role          TEXT    NOT NULL,
            action             TEXT    NOT NULL,
            module             TEXT    NOT NULL,
            affected_record_id TEXT    NULL,
            ip_address         TEXT    NOT NULL,
            user_agent         TEXT    NULL,
            status             TEXT    NOT NULL,
            anomaly_flag       TEXT    NOT NULL DEFAULT 'NORMAL',
            attempted_identifier TEXT  NULL,
            previous_hash      TEXT    NOT NULL,
            current_hash       TEXT    NOT NULL,
            created_at         TEXT    NOT NULL
        );
    SQL;

    /**
     * SQLite-compatible mirror of the production `otp_codes` table (login 2FA).
     */
    private const OTP_CODES_DDL = <<<SQL
        CREATE TABLE otp_codes (
            otp_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            code_hash   TEXT    NOT NULL,
            attempts    INTEGER NOT NULL DEFAULT 0,
            expires_at  TEXT    NOT NULL,
            used_at     TEXT    NULL,
            created_at  TEXT    NOT NULL
        );
    SQL;

    /**
     * SQLite-compatible mirror of the production `account_activations` table.
     */
    private const ACCOUNT_ACTIVATIONS_DDL = <<<SQL
        CREATE TABLE account_activations (
            activation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            token_hash    TEXT    NOT NULL UNIQUE,
            expires_at    TEXT    NOT NULL,
            used_at       TEXT    NULL,
            created_at    TEXT    NOT NULL
        );
    SQL;

    /** Create a fresh in-memory SQLite PDO with the MediShield schema loaded. */
    public static function pdo(): PDO
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec(self::USERS_DDL);
        $pdo->exec(self::AUDIT_LOGS_DDL);
        $pdo->exec(self::OTP_CODES_DDL);
        $pdo->exec(self::ACCOUNT_ACTIVATIONS_DDL);
        return $pdo;
    }
}
