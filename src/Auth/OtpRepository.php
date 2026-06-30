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
    public function latestActiveForUser(int $userId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM otp_codes
              WHERE user_id = :user_id AND used_at IS NULL
              ORDER BY otp_id DESC LIMIT 1'
        );
        $stmt->execute([':user_id' => $userId]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** Mark a single code consumed so it can never be used again. */
    public function markUsed(int $otpId): void
    {
        $this->pdo->prepare(
            'UPDATE otp_codes SET used_at = :now WHERE otp_id = :id'
        )->execute([':now' => $this->clock->nowString(), ':id' => $otpId]);
    }

    /** Increment the wrong-attempt counter for a code and return the new count. */
    public function incrementAttempts(int $otpId): int
    {
        $this->pdo->prepare(
            'UPDATE otp_codes SET attempts = attempts + 1 WHERE otp_id = :id'
        )->execute([':id' => $otpId]);

        $stmt = $this->pdo->prepare('SELECT attempts FROM otp_codes WHERE otp_id = :id');
        $stmt->execute([':id' => $otpId]);
        return (int) $stmt->fetchColumn();
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
}
