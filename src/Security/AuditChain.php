<?php

declare(strict_types=1);

namespace MediShield\Security;

/**
 * Versioned keyed hashing for audit rows and the database-resident chain head.
 *
 * Version 1 is retained exactly for historical rows. Version 2 uses a
 * domain-separated, type-aware, length-prefixed encoding so delimiters, nulls,
 * and empty strings cannot produce the same canonical message.
 */
final class AuditChain
{
    public const GENESIS = 'GENESIS';
    public const FORMAT_V1 = 1;
    public const FORMAT_V2 = 2;
    public const MINIMUM_KEY_BYTES = 32;

    private const ROW_V2_DOMAIN = 'MediShield/AuditRow/v2';
    private const HEAD_DOMAIN = 'MediShield/AuditHead/v2';
    private const KEY_CHECK_DOMAIN = 'MediShield/AuditKeyCheck/v1';

    public function __construct(
        private string $hmacKey,
        private string $keyId = 'primary'
    ) {
        if (strlen($this->hmacKey) < self::MINIMUM_KEY_BYTES) {
            throw new \InvalidArgumentException('Audit HMAC key must contain at least 32 bytes.');
        }
        if (
            $this->keyId === ''
            || strlen($this->keyId) > 64
            || preg_match('/^[A-Za-z0-9._-]+$/D', $this->keyId) !== 1
        ) {
            throw new \InvalidArgumentException('Audit key id is invalid.');
        }
    }

    public static function fromHexKey(string $hex, string $keyId = 'primary'): self
    {
        if (
            $hex === ''
            || strlen($hex) % 2 !== 0
            || preg_match('/^[0-9a-fA-F]+$/D', $hex) !== 1
        ) {
            throw new \InvalidArgumentException('Audit HMAC key hex is invalid.');
        }

        $raw = hex2bin($hex);
        if ($raw === false) {
            throw new \InvalidArgumentException('Audit HMAC key hex is invalid.');
        }

        return new self($raw, $keyId);
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    public function keyCheck(): string
    {
        return hash_hmac('sha256', self::KEY_CHECK_DOMAIN, $this->hmacKey);
    }

    public function matchesKeyCheck(string $stored): bool
    {
        return strlen($stored) === 64 && hash_equals($stored, $this->keyCheck());
    }

    /**
     * @param array<string,mixed> $entry
     */
    public function computeHash(
        array $entry,
        string $previousHash,
        ?int $formatVersion = null
    ): string {
        $version = $formatVersion ?? (int) ($entry['format_version'] ?? self::FORMAT_V1);

        return match ($version) {
            self::FORMAT_V1 => $this->computeVersionOneHash($entry, $previousHash),
            self::FORMAT_V2 => $this->computeVersionTwoHash($entry, $previousHash),
            default => throw new \InvalidArgumentException('Unsupported audit hash format version.'),
        };
    }

    /**
     * @param array<string,mixed> $head
     */
    public function computeHeadMac(array $head): string
    {
        return hash_hmac('sha256', $this->canonical(self::HEAD_DOMAIN, [
            'last_seq' => self::requiredInteger($head, 'last_seq'),
            'last_log_id' => self::nullableInteger($head['last_log_id'] ?? null),
            'head_hash' => self::requiredString($head, 'head_hash'),
            'key_id' => self::requiredString($head, 'key_id'),
            'format_version' => self::requiredInteger($head, 'format_version'),
            'key_check' => self::requiredString($head, 'key_check'),
            'updated_at' => self::requiredString($head, 'updated_at'),
        ]), $this->hmacKey);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function computeVersionOneHash(array $entry, string $previousHash): string
    {
        $parts = [
            self::legacyNullable($entry['user_id'] ?? null),
            (string) $entry['user_role'],
            (string) $entry['action'],
            (string) $entry['module'],
            self::legacyNullable($entry['affected_record_id'] ?? null),
            (string) $entry['status'],
            (string) $entry['anomaly_flag'],
            (string) $entry['created_at'],
            $previousHash,
        ];

        return base64_encode(hash_hmac('sha256', implode('|', $parts), $this->hmacKey, true));
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function computeVersionTwoHash(array $entry, string $previousHash): string
    {
        $fields = [
            'format_version' => self::FORMAT_V2,
            'seq' => self::requiredInteger($entry, 'seq'),
            'event_id' => self::requiredString($entry, 'event_id'),
            'key_id' => self::requiredString($entry, 'key_id'),
            'user_id' => self::nullableInteger($entry['user_id'] ?? null),
            'user_role' => self::requiredString($entry, 'user_role'),
            'action' => self::requiredString($entry, 'action'),
            'module' => self::requiredString($entry, 'module'),
            'affected_record_id' => self::nullableString($entry['affected_record_id'] ?? null),
            'ip_address' => self::requiredString($entry, 'ip_address'),
            'user_agent' => self::nullableString($entry['user_agent'] ?? null),
            'status' => self::requiredString($entry, 'status'),
            'anomaly_flag' => self::requiredString($entry, 'anomaly_flag'),
            'created_at' => self::requiredString($entry, 'created_at'),
            'previous_hash' => $previousHash,
        ];

        return hash_hmac('sha256', $this->canonical(self::ROW_V2_DOMAIN, $fields), $this->hmacKey);
    }

    /**
     * Every name and value is byte-length-prefixed. A one-byte type marker keeps
     * null, integer, and string values distinct even when their display text is
     * identical.
     *
     * @param array<string,int|string|null> $fields
     */
    private function canonical(string $domain, array $fields): string
    {
        $encoded = self::lengthPrefix($domain) . pack('N', count($fields));
        foreach ($fields as $name => $value) {
            $encoded .= self::lengthPrefix($name);
            if ($value === null) {
                $encoded .= "\x00" . pack('N', 0);
                continue;
            }

            $text = (string) $value;
            $encoded .= (is_int($value) ? "\x01" : "\x02") . self::lengthPrefix($text);
        }

        return $encoded;
    }

    private static function lengthPrefix(string $value): string
    {
        return pack('N', strlen($value)) . $value;
    }

    /**
     * @param array<string,mixed> $values
     */
    private static function requiredString(array $values, string $field): string
    {
        if (!array_key_exists($field, $values) || !is_string($values[$field])) {
            throw new \InvalidArgumentException('Audit field is missing or invalid: ' . $field);
        }

        return $values[$field];
    }

    /**
     * @param array<string,mixed> $values
     */
    private static function requiredInteger(array $values, string $field): int
    {
        $value = $values[$field] ?? null;
        if (is_int($value)) {
            return $value;
        }
        if (is_string($value) && preg_match('/^[0-9]+$/D', $value) === 1) {
            return (int) $value;
        }

        throw new \InvalidArgumentException('Audit integer field is missing or invalid: ' . $field);
    }

    private static function nullableInteger(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_int($value)) {
            return $value;
        }
        if (is_string($value) && preg_match('/^[0-9]+$/D', $value) === 1) {
            return (int) $value;
        }

        throw new \InvalidArgumentException('Audit nullable integer field is invalid.');
    }

    private static function nullableString(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }
        if (!is_string($value) && !is_int($value)) {
            throw new \InvalidArgumentException('Audit nullable string field is invalid.');
        }

        return (string) $value;
    }

    private static function legacyNullable(mixed $value): string
    {
        return ($value === null || $value === '') ? 'NULL' : (string) $value;
    }
}
