<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Support\Clock;
use PDO;

/**
 * OtpRepository
 * -------------
 * The only place that reads/writes the `otp_codes` table (login second factor).
 * All SQL uses PDO prepared statements with bound parameters (no concatenation),
 * and the SQL is portable so the same class runs on MySQL/MariaDB (production) and
 * in-memory SQLite (tests).
 *
 * Rows store only a HASH of the one-time code (never the plaintext). A {@see Clock}
 * is injected so `created_at` is deterministic under test.
 *
 * Column shape: otp_id, user_id, code_hash, attempts, expires_at, used_at, created_at
 */
final class OtpRepository
{
    public function __construct(
        private PDO $pdo,
        private Clock $clock
    ) {
    }

    /** Insert a new OTP row and return its id. $expiresAt is a 'Y-m-d H:i:s' UTC string. */
    public function create(int $userId, string $codeHash, string $expiresAt): int
    {
        $now = $this->clock->nowString();
        $stmt = $this->pdo->prepare(
            'INSERT INTO otp_codes (user_id, code_hash, attempts, expires_at, used_at, created_at)
             VALUES (:user_id, :code_hash, 0, :expires_at, NULL, :created_at)'
        );
        $stmt->execute([
            ':user_id'    => $userId,
            ':code_hash'  => $codeHash,
            ':expires_at' => $expiresAt,
            ':created_at' => $now,
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    /**
     * The most recent UNUSED code for a user (the one currently in play), or null.
     * We only ever consider the newest unused row so an attacker cannot replay an
     * older, superseded code.
     */
    public function latestActiveForUser(int $userId, bool $lockForUpdate = false): ?array
    {
        $lockSql = $lockForUpdate && $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql'
            ? ' FOR UPDATE'
            : '';
        $stmt = $this->pdo->prepare(
            'SELECT * FROM otp_codes
              WHERE user_id = :user_id AND used_at IS NULL
              ORDER BY otp_id DESC LIMIT 1' . $lockSql
        );
        $stmt->execute([':user_id' => $userId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** Mark a single code consumed so it can never be used again. */
    public function markUsed(int $otpId): bool
    {
        $stmt = $this->pdo->prepare(
            'UPDATE otp_codes
                SET used_at = :now
              WHERE otp_id = :id AND used_at IS NULL'
        );
        $stmt->execute([':now' => $this->clock->nowString(), ':id' => $otpId]);
        return $stmt->rowCount() === 1;
    }

    /** Increment the wrong-attempt counter for a code and return the new count. */
    public function incrementAttempts(int $otpId): ?int
    {
        $stmt = $this->pdo->prepare(
            'UPDATE otp_codes
                SET attempts = attempts + 1
              WHERE otp_id = :id AND used_at IS NULL'
        );
        $stmt->execute([':id' => $otpId]);
        if ($stmt->rowCount() !== 1) {
            return null;
        }

        $read = $this->pdo->prepare('SELECT attempts FROM otp_codes WHERE otp_id = :id');
        $read->execute([':id' => $otpId]);
        return (int) $read->fetchColumn();
    }

    /**
     * Invalidate every still-unused code for a user (mark them used). Called before
     * issuing a fresh code so a user only ever has ONE active code at a time.
     */
    public function invalidateAllForUser(int $userId): void
    {
        $this->pdo->prepare(
            'UPDATE otp_codes SET used_at = :now
              WHERE user_id = :user_id AND used_at IS NULL'
        )->execute([':now' => $this->clock->nowString(), ':user_id' => $userId]);
    }

    /**
     * Run a read/check/consume sequence atomically. Nested callers participate in
     * an existing transaction rather than attempting unsupported savepoints.
     */
    public function transactional(callable $operation): mixed
    {
        $ownsTransaction = !$this->pdo->inTransaction();
        if ($ownsTransaction) {
            $this->pdo->beginTransaction();
        }
        try {
            $result = $operation();
            if ($ownsTransaction) {
                $this->pdo->commit();
            }
            return $result;
        } catch (\Throwable $error) {
            if ($ownsTransaction && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }
}
