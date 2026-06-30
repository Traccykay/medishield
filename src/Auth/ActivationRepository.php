<?php

declare(strict_types=1);

namespace MediShield\Auth;

use MediShield\Support\Clock;
use PDO;

/**
 * ActivationRepository
 * --------------------
 * The only place that reads/writes the `account_activations` table — the one-time
 * tokens emailed to a newly-created user so they can set their own password and
 * activate their account (spec §9.2 / Deliverable).
 *
 * All SQL uses PDO prepared statements with bound parameters (no concatenation),
 * and is portable so the same class runs on MySQL/MariaDB (production) and
 * in-memory SQLite (tests).
 *
 * Security note: unlike the short OTP, the activation token is high-entropy
 * (32 random bytes), so we store a deterministic SHA-256 HASH of it. Determinism
 * lets us look the row up by hash; the high entropy makes SHA-256 safe here (no
 * feasible brute force, unlike a 6-char OTP which needs bcrypt). The plaintext
 * token only ever exists in the emailed link.
 *
 * Column shape: activation_id, user_id, token_hash, expires_at, used_at, created_at
 */
final class ActivationRepository
{
    public function __construct(
        private PDO $pdo,
        private Clock $clock
    ) {
    }

    /** Insert a new activation row and return its id. $expiresAt is 'Y-m-d H:i:s' UTC. */
    public function create(int $userId, string $tokenHash, string $expiresAt): int
    {
        $now = $this->clock->nowString();
        $stmt = $this->pdo->prepare(
            'INSERT INTO account_activations
                 (user_id, token_hash, expires_at, used_at, created_at)
             VALUES (:user_id, :token_hash, :expires_at, NULL, :created_at)'
        );
        $stmt->execute([
            ':user_id'    => $userId,
            ':token_hash' => $tokenHash,
            ':expires_at' => $expiresAt,
            ':created_at' => $now,
        ]);
        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Look up an UNUSED activation row by its token hash, or null. We match on the
     * hash (never the plaintext) and ignore already-consumed rows.
     */
    public function findActiveByHash(string $tokenHash): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM account_activations
              WHERE token_hash = :token_hash AND used_at IS NULL
              LIMIT 1'
        );
        $stmt->execute([':token_hash' => $tokenHash]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** Mark a token consumed so the activation link can never be reused. */
    public function markUsed(int $activationId): void
    {
        $this->pdo->prepare(
            'UPDATE account_activations SET used_at = :now WHERE activation_id = :id'
        )->execute([':now' => $this->clock->nowString(), ':id' => $activationId]);
    }

    /**
     * Invalidate every still-unused token for a user (mark them used). Called before
     * issuing a fresh token so only one activation link is ever live.
     */
    public function invalidateAllForUser(int $userId): void
    {
        $this->pdo->prepare(
            'UPDATE account_activations SET used_at = :now
              WHERE user_id = :user_id AND used_at IS NULL'
        )->execute([':now' => $this->clock->nowString(), ':user_id' => $userId]);
    }
}
