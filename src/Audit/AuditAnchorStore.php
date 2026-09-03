<?php

declare(strict_types=1);

namespace MediShield\Audit;

use MediShield\Support\Clock;

/**
 * Append-only JSONL commitments stored independently from the application DB.
 *
 * The anchor key must be separate from the audit-row key. This file detects a
 * database rollback only when its storage and key are outside the compromised
 * database/application trust boundary.
 */
final class AuditAnchorStore
{
    private const MINIMUM_KEY_BYTES = 32;
    private const KEY_CHECK_DOMAIN = 'MediShield/AuditAnchorKeyCheck/v1';
    private const RECORD_DOMAIN = 'MediShield/AuditAnchor/v1';

    public function __construct(
        private string $path,
        private string $key,
        private string $keyId,
        private Clock $clock
    ) {
        if (strlen($this->key) < self::MINIMUM_KEY_BYTES) {
            throw new \InvalidArgumentException('Audit anchor key must contain at least 32 bytes.');
        }
        if (
            $this->keyId === ''
            || strlen($this->keyId) > 64
            || preg_match('/^[A-Za-z0-9._-]+$/D', $this->keyId) !== 1
        ) {
            throw new \InvalidArgumentException('Audit anchor key id is invalid.');
        }
        $anchorPath = self::normalizeAbsolutePath($this->path);
        $publicRoot = self::normalizeAbsolutePath(dirname(__DIR__, 2) . '/public');
        if (
            $anchorPath === null
            || $publicRoot === null
            || $anchorPath === $publicRoot
            || str_starts_with($anchorPath, $publicRoot . '/')
        ) {
            throw new \InvalidArgumentException('Audit anchor path must be outside the public web root.');
        }
    }

    public static function fromHexKey(
        string $path,
        string $hex,
        string $keyId,
        Clock $clock
    ): self {
        if (
            $hex === ''
            || strlen($hex) % 2 !== 0
            || preg_match('/^[0-9a-fA-F]+$/D', $hex) !== 1
        ) {
            throw new \InvalidArgumentException('Audit anchor key hex is invalid.');
        }
        $raw = hex2bin($hex);
        if ($raw === false) {
            throw new \InvalidArgumentException('Audit anchor key hex is invalid.');
        }
        return new self($path, $raw, $keyId, $clock);
    }

    /**
     * Append the supplied database head. Returns false when that exact head was
     * already anchored, making scheduled retries idempotent.
     *
     * @param array<string,mixed> $head
     */
    public function anchor(array $head): bool
    {
        $directory = dirname($this->path);
        if (!is_dir($directory)) {
            throw new \RuntimeException('Audit anchor directory does not exist.');
        }
        if (is_link($this->path)) {
            throw new \RuntimeException('Audit anchor path must not be a symbolic link.');
        }

        $handle = fopen($this->path, 'c+b');
        if ($handle === false) {
            throw new \RuntimeException('Audit anchor file could not be opened.');
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new \RuntimeException('Audit anchor file could not be locked.');
            }
            rewind($handle);
            $content = stream_get_contents($handle);
            if ($content === false) {
                throw new \RuntimeException('Audit anchor file could not be read.');
            }
            $parsed = $this->parse($content);
            if ($parsed['state'] !== 'PASS') {
                throw new \RuntimeException('Existing audit anchor history is not valid.');
            }
            $last = $parsed['latest'];
            $sequence = (int) ($head['last_seq'] ?? -1);
            $headHash = (string) ($head['head_hash'] ?? '');
            $auditKeyId = (string) ($head['key_id'] ?? '');
            if ($sequence < 0 || $headHash === '' || $auditKeyId === '') {
                throw new \InvalidArgumentException('Audit chain head is incomplete.');
            }

            if ($last !== null) {
                $lastSequence = (int) $last['anchor_seq'];
                if ($sequence < $lastSequence) {
                    throw new \RuntimeException('Refusing to anchor a database rollback.');
                }
                if ($sequence === $lastSequence) {
                    if (
                        hash_equals((string) $last['head_hash'], $headHash)
                        && (string) $last['audit_key_id'] === $auditKeyId
                    ) {
                        return false;
                    }
                    throw new \RuntimeException('Refusing a conflicting anchor at the same sequence.');
                }
            }

            $record = [
                'anchor_version' => 1,
                'anchor_seq' => $sequence,
                'log_id' => isset($head['last_log_id']) ? (int) $head['last_log_id'] : null,
                'head_hash' => $headHash,
                'audit_key_id' => $auditKeyId,
                'anchor_key_id' => $this->keyId,
                'anchored_at' => $this->clock->nowString(),
                'key_check' => $this->keyCheck(),
                'previous_anchor_mac' => $last['anchor_mac'] ?? 'GENESIS',
            ];
            $record['anchor_mac'] = $this->recordMac($record);
            $json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

            fseek($handle, 0, SEEK_END);
            if (fwrite($handle, $json . "\n") === false || !fflush($handle)) {
                throw new \RuntimeException('Audit anchor file could not be durably appended.');
            }
            if (function_exists('fsync') && !fsync($handle)) {
                throw new \RuntimeException('Audit anchor file synchronization failed.');
            }
            return true;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * @param array<string,mixed> $head
     * @return array<string,mixed>
     */
    public function verifyHead(array $head): array
    {
        if (!is_file($this->path)) {
            return $this->result('UNKNOWN', 'EXTERNAL_ANCHOR_MISSING');
        }
        if (is_link($this->path)) {
            return $this->result('UNKNOWN', 'ANCHOR_STORAGE_UNSAFE');
        }

        try {
            $content = file_get_contents($this->path);
            if ($content === false) {
                return $this->result('UNKNOWN', 'ANCHOR_READ_ERROR');
            }
            $parsed = $this->parse($content);
            if ($parsed['state'] !== 'PASS') {
                return $parsed;
            }
            $latest = $parsed['latest'];
            if ($latest === null) {
                return $this->result('UNKNOWN', 'EXTERNAL_ANCHOR_MISSING');
            }

            $databaseSequence = (int) $head['last_seq'];
            $anchorSequence = (int) $latest['anchor_seq'];
            if ($databaseSequence < $anchorSequence) {
                return $this->result('FAIL', 'DATABASE_ROLLBACK_DETECTED', $anchorSequence);
            }
            if ($databaseSequence > $anchorSequence) {
                return $this->result('UNKNOWN', 'UNANCHORED_DATABASE_SUFFIX', $anchorSequence);
            }
            if (
                !hash_equals((string) $latest['head_hash'], (string) $head['head_hash'])
                || (string) $latest['audit_key_id'] !== (string) $head['key_id']
            ) {
                return $this->result('FAIL', 'ANCHOR_HEAD_MISMATCH', $anchorSequence);
            }
            return $this->result('PASS', 'ANCHORED_CHAIN_VALID', $anchorSequence);
        } catch (\Throwable) {
            return $this->result('UNKNOWN', 'ANCHOR_READ_ERROR');
        }
    }

    /**
     * @return array{state:string,reason:string,latest:?array<string,mixed>,anchor_seq:?int}
     */
    private function parse(string $content): array
    {
        $latest = null;
        $previousMac = 'GENESIS';
        $previousSequence = -1;
        foreach (preg_split('/\r\n|\r|\n/', $content) ?: [] as $line) {
            if ($line === '') {
                continue;
            }
            $record = json_decode($line, true, flags: JSON_THROW_ON_ERROR);
            if (!is_array($record)) {
                return $this->result('FAIL', 'ANCHOR_RECORD_INVALID');
            }
            if (!hash_equals((string) ($record['key_check'] ?? ''), $this->keyCheck())) {
                return $this->result('UNKNOWN', 'ANCHOR_KEY_MISMATCH');
            }
            if ((string) ($record['anchor_key_id'] ?? '') !== $this->keyId) {
                return $this->result('UNKNOWN', 'ANCHOR_KEY_ID_MISMATCH');
            }
            if ((string) ($record['previous_anchor_mac'] ?? '') !== $previousMac) {
                return $this->result('FAIL', 'ANCHOR_CHAIN_LINK_MISMATCH');
            }
            $sequence = (int) ($record['anchor_seq'] ?? -1);
            if ($sequence <= $previousSequence) {
                return $this->result('FAIL', 'ANCHOR_SEQUENCE_NOT_MONOTONIC');
            }
            $expected = $this->recordMac($record);
            if (!hash_equals((string) ($record['anchor_mac'] ?? ''), $expected)) {
                return $this->result('FAIL', 'ANCHOR_MAC_INVALID');
            }
            $previousSequence = $sequence;
            $previousMac = (string) $record['anchor_mac'];
            $latest = $record;
        }

        return [
            'state' => 'PASS',
            'reason' => 'ANCHOR_HISTORY_VALID',
            'latest' => $latest,
            'anchor_seq' => $latest === null ? null : (int) $latest['anchor_seq'],
        ];
    }

    /**
     * @param array<string,mixed> $record
     */
    private function recordMac(array $record): string
    {
        $fields = [
            'anchor_version' => (int) ($record['anchor_version'] ?? 0),
            'anchor_seq' => (int) ($record['anchor_seq'] ?? -1),
            'log_id' => $record['log_id'] === null ? null : (int) $record['log_id'],
            'head_hash' => (string) ($record['head_hash'] ?? ''),
            'audit_key_id' => (string) ($record['audit_key_id'] ?? ''),
            'anchor_key_id' => (string) ($record['anchor_key_id'] ?? ''),
            'anchored_at' => (string) ($record['anchored_at'] ?? ''),
            'key_check' => (string) ($record['key_check'] ?? ''),
            'previous_anchor_mac' => (string) ($record['previous_anchor_mac'] ?? ''),
        ];
        $encoded = self::lengthPrefix(self::RECORD_DOMAIN) . pack('N', count($fields));
        foreach ($fields as $name => $value) {
            $encoded .= self::lengthPrefix($name);
            if ($value === null) {
                $encoded .= "\x00" . pack('N', 0);
            } else {
                $text = (string) $value;
                $encoded .= (is_int($value) ? "\x01" : "\x02") . self::lengthPrefix($text);
            }
        }
        return hash_hmac('sha256', $encoded, $this->key);
    }

    private function keyCheck(): string
    {
        return hash_hmac('sha256', self::KEY_CHECK_DOMAIN, $this->key);
    }

    private static function lengthPrefix(string $value): string
    {
        return pack('N', strlen($value)) . $value;
    }

    private static function normalizeAbsolutePath(string $path): ?string
    {
        if ($path === '' || str_contains($path, "\0")) {
            return null;
        }
        $path = str_replace('\\', '/', $path);
        if (preg_match('/^[A-Za-z]:\//D', $path) === 1) {
            $prefix = strtolower(substr($path, 0, 2));
            $path = substr($path, 3);
        } elseif (str_starts_with($path, '/')) {
            $prefix = '';
            $path = ltrim($path, '/');
        } else {
            return null;
        }
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                if ($segments === []) {
                    return null;
                }
                array_pop($segments);
                continue;
            }
            $segments[] = strtolower($segment);
        }
        return $prefix . '/' . implode('/', $segments);
    }

    /**
     * @return array<string,mixed>
     */
    private function result(string $state, string $reason, ?int $anchorSequence = null): array
    {
        return [
            'state' => $state,
            'reason' => $reason,
            'anchor_seq' => $anchorSequence,
            'limitations' => $state === 'PASS'
                ? ['Anchor trust depends on separate key and storage administration.']
                : [],
        ];
    }
}
