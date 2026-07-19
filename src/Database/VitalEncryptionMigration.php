<?php

declare(strict_types=1);

namespace MediShield\Database;

use MediShield\Security\Crypto;
use PDO;

/**
 * Encrypts the legacy plaintext vitals schema after its encrypted staging columns
 * have been added by the SQL migration. This must run with the application key:
 * SQL alone cannot create AES-256-GCM ciphertext compatible with Crypto.
 */
final class VitalEncryptionMigration
{
    /** @var array<string, string> */
    private const LEGACY_TO_ENCRYPTED = [
        'temperature_c' => 'temperature_encrypted',
        'systolic_mmhg' => 'systolic_encrypted',
        'diastolic_mmhg' => 'diastolic_encrypted',
        'pulse_bpm' => 'pulse_encrypted',
        'weight_kg' => 'weight_encrypted',
        'symptoms' => 'symptoms_encrypted',
    ];

    public function __construct(private PDO $pdo, private Crypto $crypto)
    {
    }

    /**
     * Encrypt every legacy row, then remove every plaintext source column.
     *
     * Re-running is safe: after successful completion the first legacy column is
     * absent; if interrupted before cleanup, already-populated ciphertext is kept.
     */
    public function migrate(): void
    {
        if (!$this->hasColumn('temperature_c')) {
            return;
        }

        foreach (self::LEGACY_TO_ENCRYPTED as $encrypted) {
            if (!$this->hasColumn($encrypted)) {
                throw new \RuntimeException('Encrypted vitals staging column is missing: ' . $encrypted);
            }
        }

        $rows = $this->pdo->query('SELECT * FROM vitals')->fetchAll();
        $update = $this->pdo->prepare(
            'UPDATE vitals
                SET temperature_encrypted = COALESCE(temperature_encrypted, :temperature),
                    systolic_encrypted = COALESCE(systolic_encrypted, :systolic),
                    diastolic_encrypted = COALESCE(diastolic_encrypted, :diastolic),
                    pulse_encrypted = COALESCE(pulse_encrypted, :pulse),
                    weight_encrypted = COALESCE(weight_encrypted, :weight),
                    symptoms_encrypted = COALESCE(symptoms_encrypted, :symptoms)
              WHERE vitals_id = :vitals_id'
        );

        $this->pdo->beginTransaction();
        try {
            foreach ($rows as $row) {
                $update->execute([
                    ':temperature' => $this->crypto->encrypt((string) $row['temperature_c']),
                    ':systolic' => $this->crypto->encrypt((string) $row['systolic_mmhg']),
                    ':diastolic' => $this->crypto->encrypt((string) $row['diastolic_mmhg']),
                    ':pulse' => $this->crypto->encrypt((string) $row['pulse_bpm']),
                    ':weight' => $this->crypto->encrypt((string) $row['weight_kg']),
                    ':symptoms' => $row['symptoms'] === null ? null : $this->crypto->encrypt((string) $row['symptoms']),
                    ':vitals_id' => $row['vitals_id'],
                ]);
            }
            $this->pdo->commit();
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }

        foreach (array_keys(self::LEGACY_TO_ENCRYPTED) as $legacy) {
            $this->pdo->exec('ALTER TABLE vitals DROP COLUMN ' . $legacy);
        }

        if ($this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'sqlite') {
            $this->pdo->exec(
                'ALTER TABLE vitals
                    MODIFY temperature_encrypted TEXT NOT NULL,
                    MODIFY systolic_encrypted TEXT NOT NULL,
                    MODIFY diastolic_encrypted TEXT NOT NULL,
                    MODIFY pulse_encrypted TEXT NOT NULL,
                    MODIFY weight_encrypted TEXT NOT NULL,
                    MODIFY symptoms_encrypted TEXT NULL'
            );
        }
    }

    private function hasColumn(string $column): bool
    {
        if ($this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite') {
            $columns = $this->pdo->query('PRAGMA table_info(vitals)')->fetchAll();
            return in_array($column, array_column($columns, 'name'), true);
        }

        $columns = $this->pdo->query('SHOW COLUMNS FROM vitals')->fetchAll();
        return in_array($column, array_column($columns, 'Field'), true);
    }
}
