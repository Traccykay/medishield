<?php

declare(strict_types=1);

namespace MediShield\Security;

use MediShield\Support\Clock;
use PDO;
use PDOException;

/**
 * Database-backed fixed-window request throttle for unauthenticated endpoints.
 *
 * The database stores an HMAC-derived scope instead of the raw IP address. This
 * makes the limit survive a new browser session without unnecessarily retaining
 * another copy of a visitor's network identifier.
 */
final class RequestThrottle
{
    private string $scopeKey;

    public function __construct(
        private PDO $pdo,
        private Clock $clock,
        string $scopeKeyHex
    ) {
        if (
            strlen($scopeKeyHex) % 2 !== 0
            || preg_match('/^[0-9a-fA-F]+$/D', $scopeKeyHex) !== 1
        ) {
            throw new \InvalidArgumentException('Request throttle key must be valid hexadecimal.');
        }
        $raw = hex2bin($scopeKeyHex);
        if ($raw === false || strlen($raw) < 32) {
            throw new \InvalidArgumentException('Request throttle key must contain at least 32 bytes.');
        }
        $this->scopeKey = $raw;
    }

    /**
     * Record one request and return whether it is inside the configured budget.
     *
     * A successful request consumes one unit. Once the limit is exhausted, no
     * further writes are made until the fixed window expires.
     */
    public function allow(string $action, string $clientIp, int $limit, int $windowSeconds): bool
    {
        if ($action === '' || $limit < 1 || $windowSeconds < 1) {
            throw new \InvalidArgumentException('Request throttle policy values must be positive.');
        }

        $scopeHash = hash_hmac('sha256', "request-throttle\0{$action}\0{$clientIp}", $this->scopeKey);
        $now = $this->clock->now();
        $nowString = $now->format('Y-m-d H:i:s');
        $cutoff = $now->sub(new \DateInterval('PT' . $windowSeconds . 'S'))->format('Y-m-d H:i:s');

        // The conditional update is the normal fast path and prevents concurrent
        // requests from each observing the same remaining budget.
        $increment = $this->pdo->prepare(
            'UPDATE request_throttles
                SET attempt_count = attempt_count + 1
              WHERE scope_hash = :scope_hash
                AND window_started_at > :cutoff
                AND attempt_count < :limit'
        );
        $increment->execute([
            ':scope_hash' => $scopeHash,
            ':cutoff' => $cutoff,
            ':limit' => $limit,
        ]);
        if ($increment->rowCount() === 1) {
            return true;
        }

        // A prior window can be safely replaced by this new attempt.
        $reset = $this->pdo->prepare(
            'UPDATE request_throttles
                SET attempt_count = 1, window_started_at = :now
              WHERE scope_hash = :scope_hash
                AND window_started_at <= :cutoff'
        );
        $reset->execute([
            ':now' => $nowString,
            ':scope_hash' => $scopeHash,
            ':cutoff' => $cutoff,
        ]);
        if ($reset->rowCount() === 1) {
            return true;
        }

        try {
            $create = $this->pdo->prepare(
                'INSERT INTO request_throttles (scope_hash, attempt_count, window_started_at)
                 VALUES (:scope_hash, 1, :now)'
            );
            $create->execute([':scope_hash' => $scopeHash, ':now' => $nowString]);
            return true;
        } catch (PDOException $exception) {
            // Another request may have created this scope between our conditional
            // update and insert. Retry the bounded update once; any other database
            // failure must remain visible to the caller.
            if (!$this->isUniqueViolation($exception)) {
                throw $exception;
            }
        }

        $increment->execute([
            ':scope_hash' => $scopeHash,
            ':cutoff' => $cutoff,
            ':limit' => $limit,
        ]);

        return $increment->rowCount() === 1;
    }

    private function isUniqueViolation(PDOException $exception): bool
    {
        $sqlState = (string) $exception->getCode();

        return $sqlState === '23000' || $sqlState === '19';
    }
}
