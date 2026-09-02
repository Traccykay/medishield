<?php

declare(strict_types=1);

namespace MediShield\Support;

/**
 * Clock
 * -----
 * A tiny, injectable source of "the current time".
 *
 * Why does this exist? Time-dependent logic (account lockout windows, audit
 * timestamps) is impossible to test reliably if it calls `time()` / `new
 * DateTimeImmutable('now')` directly. By depending on a Clock instead, tests can
 * inject a *fixed* time and assert exact behaviour.
 *
 * Production code uses the default constructor (real system clock, UTC).
 * Tests use:  new Clock(fn() => new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC')))
 *
 * All times are produced in UTC, because the audit log and lockout math must be
 * timezone-stable (see spec §10.1).
 */
final class Clock
{
    public const DATABASE_TIMESTAMP_FORMAT = 'Y-m-d H:i:s';

    /** @var callable():\DateTimeImmutable */
    private $nowFn;

    /**
     * @param (callable():\DateTimeImmutable)|null $nowFn Optional override returning the "current" time.
     *                                                    Defaults to the real system clock in UTC.
     */
    public function __construct(?callable $nowFn = null)
    {
        $this->nowFn = $nowFn ?? static fn (): \DateTimeImmutable =>
            new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    /** Current time as a DateTimeImmutable (UTC). */
    public function now(): \DateTimeImmutable
    {
        return ($this->nowFn)();
    }

    /** Current time formatted as a MySQL/SQLite-friendly UTC string: 'Y-m-d H:i:s'. */
    public function nowString(): string
    {
        return $this->now()->format(self::DATABASE_TIMESTAMP_FORMAT);
    }

    /**
     * Current time plus a number of minutes, as a 'Y-m-d H:i:s' UTC string.
     * Used to compute account `locked_until` timestamps.
     */
    public function plusMinutesString(int $minutes): string
    {
        return $this->now()
            ->add(new \DateInterval('PT' . max(0, $minutes) . 'M'))
            ->format(self::DATABASE_TIMESTAMP_FORMAT);
    }

    /**
     * Parse the exact UTC representation persisted by MediShield.
     *
     * PHP's general DateTime parser normalizes impossible dates such as February
     * 30 instead of rejecting them. Security decisions must not accept that
     * normalization, so both the input shape and round-trip value are required.
     */
    public static function parseDatabaseTimestamp(mixed $value): ?\DateTimeImmutable
    {
        if (
            !is_string($value)
            || preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $value) !== 1
        ) {
            return null;
        }

        $parsed = \DateTimeImmutable::createFromFormat(
            '!' . self::DATABASE_TIMESTAMP_FORMAT,
            $value,
            new \DateTimeZone('UTC')
        );

        if ($parsed === false || $parsed->format(self::DATABASE_TIMESTAMP_FORMAT) !== $value) {
            return null;
        }

        return $parsed;
    }
}
