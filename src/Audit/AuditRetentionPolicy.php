<?php

declare(strict_types=1);

namespace MediShield\Audit;

/**
 * Strict, testable parser for the retention CLI's safety-critical options.
 */
final class AuditRetentionPolicy
{
    public function __construct(
        public readonly int $retentionDays,
        public readonly int $batchSize,
        public readonly bool $dryRun
    ) {
    }

    /**
     * @param string[] $arguments
     * @param array<string,mixed> $config
     */
    public static function fromArguments(array $arguments, array $config): self
    {
        $minimum = self::positiveInteger(
            $config['minimum_pii_retention_days'] ?? 30,
            'minimum retention'
        );
        $days = self::positiveInteger(
            $config['pii_retention_days'] ?? 90,
            'configured retention'
        );
        $batchSize = self::positiveInteger(
            $config['retention_batch_size'] ?? 250,
            'configured batch size'
        );
        $dryRun = false;
        $seen = [];

        for ($index = 1; $index < count($arguments); $index++) {
            $argument = $arguments[$index];
            if ($argument === '--dry-run') {
                self::markOnce($seen, 'dry-run');
                $dryRun = true;
                continue;
            }

            [$name, $inline] = array_pad(explode('=', $argument, 2), 2, null);
            if ($name !== '--days' && $name !== '--batch-size') {
                throw new \InvalidArgumentException('Unknown audit retention option.');
            }
            self::markOnce($seen, $name);

            $value = $inline;
            if ($value === null) {
                $index++;
                $value = $arguments[$index] ?? null;
            }
            if (!is_string($value) || preg_match('/^[1-9][0-9]*$/D', $value) !== 1) {
                throw new \InvalidArgumentException('Audit retention options require positive integers.');
            }

            if ($name === '--days') {
                $days = (int) $value;
            } else {
                $batchSize = (int) $value;
            }
        }

        if ($days < $minimum) {
            throw new \InvalidArgumentException('Requested retention is below the configured safety floor.');
        }
        if ($batchSize > 1000) {
            throw new \InvalidArgumentException('Audit retention batch size cannot exceed 1000.');
        }

        return new self($days, $batchSize, $dryRun);
    }

    private static function positiveInteger(mixed $value, string $name): int
    {
        if (
            !is_int($value)
            && (!is_string($value) || preg_match('/^[1-9][0-9]*$/D', $value) !== 1)
        ) {
            throw new \InvalidArgumentException('Invalid ' . $name . '.');
        }
        $parsed = (int) $value;
        if ($parsed < 1) {
            throw new \InvalidArgumentException('Invalid ' . $name . '.');
        }
        return $parsed;
    }

    /**
     * @param array<string,bool> $seen
     */
    private static function markOnce(array &$seen, string $name): void
    {
        if (isset($seen[$name])) {
            throw new \InvalidArgumentException('Duplicate audit retention option.');
        }
        $seen[$name] = true;
    }
}
