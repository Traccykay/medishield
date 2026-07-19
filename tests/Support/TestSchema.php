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

    /** SQLite-compatible mirror of the production `patients` table. */
    private const PATIENTS_DDL = <<<SQL
        CREATE TABLE patients (
            patient_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id           INTEGER NULL,
            patient_number    TEXT    NOT NULL UNIQUE,
            full_name         TEXT    NOT NULL,
            date_of_birth     TEXT    NOT NULL,
            gender            TEXT    NOT NULL,
            phone             TEXT    NULL,
            address           TEXT    NULL,
            emergency_contact TEXT    NULL,
            created_at        TEXT    NOT NULL
        );
    SQL;

    /** SQLite-compatible mirror of the production `patient_assignments` table. */
    private const PATIENT_ASSIGNMENTS_DDL = <<<SQL
        CREATE TABLE patient_assignments (
            assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id    INTEGER NOT NULL,
            staff_user_id INTEGER NOT NULL,
            assigned_by   INTEGER NOT NULL,
            active        INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT    NOT NULL,
            UNIQUE (patient_id, staff_user_id)
        );
    SQL;

    private const VISITS_DDL = <<<SQL
        CREATE TABLE visits (
            visit_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id       INTEGER NOT NULL,
            receptionist_id  INTEGER NOT NULL,
            nurse_id         INTEGER NULL,
            doctor_id        INTEGER NULL,
            active_doctor_id INTEGER NULL UNIQUE,
            payment_method   TEXT NOT NULL,
            insurer          TEXT NULL,
            status           TEXT NOT NULL,
            created_at       TEXT NOT NULL,
            updated_at       TEXT NOT NULL
        );
    SQL;

    private const VITALS_DDL = <<<SQL
        CREATE TABLE vitals (
            vitals_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id     INTEGER NOT NULL,
            nurse_id       INTEGER NOT NULL,
            temperature_encrypted TEXT NOT NULL,
            systolic_encrypted    TEXT NOT NULL,
            diastolic_encrypted   TEXT NOT NULL,
            pulse_encrypted       TEXT NOT NULL,
            weight_encrypted      TEXT NOT NULL,
            symptoms_encrypted    TEXT NULL,
            created_at     TEXT    NOT NULL
        );
    SQL;

    private const MEDICAL_RECORDS_DDL = <<<SQL
        CREATE TABLE medical_records (
            record_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id          INTEGER NOT NULL,
            doctor_id           INTEGER NOT NULL,
            diagnosis_encrypted TEXT    NOT NULL,
            treatment_encrypted TEXT    NULL,
            created_at          TEXT    NOT NULL,
            updated_at          TEXT    NOT NULL
        );
    SQL;

    private const LAB_REQUESTS_DDL = <<<SQL
        CREATE TABLE lab_requests (
            lab_request_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id     INTEGER NOT NULL,
            record_id      INTEGER NOT NULL,
            doctor_id      INTEGER NOT NULL,
            test_name      TEXT    NOT NULL,
            reason         TEXT    NULL,
            status         TEXT    NOT NULL DEFAULT 'pending',
            created_at     TEXT    NOT NULL
        );
    SQL;

    private const LAB_RESULTS_DDL = <<<SQL
        CREATE TABLE lab_results (
            lab_result_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            lab_request_id    INTEGER NOT NULL UNIQUE,
            patient_id        INTEGER NOT NULL,
            lab_technician_id INTEGER NOT NULL,
            result_encrypted  TEXT    NOT NULL,
            created_at        TEXT    NOT NULL
        );
    SQL;

    private const PRESCRIPTIONS_DDL = <<<SQL
        CREATE TABLE prescriptions (
            prescription_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id             INTEGER NOT NULL,
            record_id              INTEGER NOT NULL,
            doctor_id              INTEGER NOT NULL,
            medication_encrypted   TEXT    NOT NULL,
            dosage_encrypted       TEXT    NOT NULL,
            instructions_encrypted TEXT    NULL,
            status                 TEXT    NOT NULL DEFAULT 'pending',
            created_at             TEXT    NOT NULL
        );
    SQL;

    private const DISPENSING_RECORDS_DDL = <<<SQL
        CREATE TABLE dispensing_records (
            dispensing_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            prescription_id INTEGER NOT NULL,
            patient_id      INTEGER NOT NULL,
            pharmacist_id   INTEGER NOT NULL,
            status          TEXT    NOT NULL DEFAULT 'dispensed',
            remarks         TEXT    NULL,
            created_at      TEXT    NOT NULL
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
        $pdo->exec(self::PATIENTS_DDL);
        $pdo->exec(self::PATIENT_ASSIGNMENTS_DDL);
        $pdo->exec(self::VISITS_DDL);
        $pdo->exec(self::VITALS_DDL);
        $pdo->exec(self::MEDICAL_RECORDS_DDL);
        $pdo->exec(self::LAB_REQUESTS_DDL);
        $pdo->exec(self::LAB_RESULTS_DDL);
        $pdo->exec(self::PRESCRIPTIONS_DDL);
        $pdo->exec(self::DISPENSING_RECORDS_DDL);
        return $pdo;
    }
}
