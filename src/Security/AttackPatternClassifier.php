<?php

declare(strict_types=1);

namespace MediShield\Security;

/**
 * Detects a deliberately small set of high-confidence web-attack signatures.
 *
 * This is forensic classification and defence in depth, not a substitute for
 * prepared SQL or contextual output encoding. Conservative signatures avoid
 * labelling ordinary clinical prose as malicious. Raw payloads are never copied
 * into the hash-chained audit event.
 */
final class AttackPatternClassifier
{
    /** @param array<array-key,mixed> $payload */
    public static function classify(array $payload): ?string
    {
        foreach (self::strings($payload) as $value) {
            if (self::looksLikeSqlInjection($value)) {
                return 'SQL_INJECTION_ATTEMPT';
            }
            if (self::looksLikeXss($value)) {
                return 'XSS_ATTEMPT';
            }
        }

        return null;
    }

    /** @param array<array-key,mixed> $payload @return list<string> */
    private static function strings(array $payload): array
    {
        $values = [];
        $pending = array_values($payload);
        while ($pending !== [] && count($values) < 100) {
            $value = array_pop($pending);
            if (is_array($value)) {
                foreach ($value as $nested) {
                    $pending[] = $nested;
                }
            } elseif (is_string($value)) {
                $values[] = mb_substr($value, 0, 4096);
            }
        }
        return $values;
    }

    private static function looksLikeSqlInjection(string $value): bool
    {
        return preg_match('/\bunion\s+(?:all\s+)?select\b/i', $value) === 1
            || preg_match('/[\'"`]\s*(?:or|and)\s+(?:[\'"`][^\'"`]*[\'"`]|\d+)\s*=\s*(?:[\'"`][^\'"`]*[\'"`]|\d+)/i', $value) === 1
            || preg_match('/;\s*(?:drop|alter|truncate|delete|insert|update)\b/i', $value) === 1
            || preg_match('/\b(?:sleep|benchmark)\s*\(/i', $value) === 1;
    }

    private static function looksLikeXss(string $value): bool
    {
        return preg_match('/<\s*script\b/i', $value) === 1
            || preg_match('/<\s*(?:img|svg|iframe|object)\b[^>]*\bon[a-z]+\s*=/i', $value) === 1
            || preg_match('/\bon(?:error|load|click|focus)\s*=/i', $value) === 1
            || preg_match('/javascript\s*:/i', $value) === 1;
    }
}
