<?php

declare(strict_types=1);

namespace MediShield\Security;

/**
 * AuditChain
 * ----------
 * Computes the tamper-evident hash for an audit-log entry (spec §9.8).
 *
 * Every audit row stores `previous_hash` and `current_hash`. The current hash is
 * an HMAC-SHA256 over the row's key fields *plus the previous row's hash*, keyed
 * by a secret (`audit_hmac_key`). This forms a hash chain:
 *
 *     row[n].current_hash = HMAC(key, fields[n] | row[n-1].current_hash)
 *
 * Why HMAC with a secret key (not a plain hash)? Because the realistic forensic
 * adversary has database access. A plain hash chain could be fully recomputed by
 * anyone who edits a row. With a server-side secret key they cannot forge valid
 * hashes, so any edit is detectable by re-running verification.
 *
 * The very first entry uses {@see GENESIS} as its previous hash.
 *
 * NOTE: this class only computes hashes. Serialized writing (SELECT ... FOR UPDATE
 * of the last row, then INSERT, in one transaction) is the audit *writer's* job,
 * so the chain stays unbroken under concurrent requests.
 */
final class AuditChain
{
    /** Previous-hash sentinel for the first row in the chain. */
    public const GENESIS = 'GENESIS';

    /** @param string $hmacKey Secret key (raw bytes) used for HMAC-SHA256. */
    public function __construct(private string $hmacKey)
    {
        if ($this->hmacKey === '') {
            throw new \InvalidArgumentException('Audit HMAC key must not be empty.');
        }
    }

    /** Build from a hex-encoded key (as stored in config `audit_hmac_key_hex`). */
    public static function fromHexKey(string $hex): self
    {
        $raw = @hex2bin($hex);
        if ($raw === false) {
            throw new \InvalidArgumentException('Audit HMAC key hex is invalid.');
        }
        return new self($raw);
    }

    /**
     * Compute the current hash for an audit entry.
     *
     * The canonical message is the following fields joined by '|', in this exact
     * order (spec §9.8). NULL user_id / affected_record_id are rendered as the
     * literal string "NULL" so the message is unambiguous:
     *
     *   user_id | user_role | action | module | affected_record_id | status |
     *   anomaly_flag | created_at | previous_hash
     *
     * @param array{
     *     user_id?: int|string|null,
     *     user_role: string,
     *     action: string,
     *     module: string,
     *     affected_record_id?: int|string|null,
     *     status: string,
     *     anomaly_flag: string,
     *     created_at: string
     * } $entry
     * @param string $previousHash The prior row's current_hash, or {@see GENESIS}.
     * @return string base64-encoded HMAC-SHA256.
     */
    public function computeHash(array $entry, string $previousHash): string
    {
        $parts = [
            self::nullable($entry['user_id'] ?? null),
            (string) $entry['user_role'],
            (string) $entry['action'],
            (string) $entry['module'],
            self::nullable($entry['affected_record_id'] ?? null),
            (string) $entry['status'],
            (string) $entry['anomaly_flag'],
            (string) $entry['created_at'],
            $previousHash,
        ];

        $message = implode('|', $parts);
        return base64_encode(hash_hmac('sha256', $message, $this->hmacKey, true));
    }

    /** Render a value for the canonical message, mapping null to the literal "NULL". */
    private static function nullable(int|string|null $value): string
    {
        return ($value === null || $value === '') ? 'NULL' : (string) $value;
    }
}
