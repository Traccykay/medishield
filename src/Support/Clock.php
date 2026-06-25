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
        return $this->now()->format('Y-m-d H:i:s');
    }

    /**
     * Current time plus a number of minutes, as a 'Y-m-d H:i:s' UTC string.
     * Used to compute account `locked_until` timestamps.
     */
    public function plusMinutesString(int $minutes): string
    {
        return $this->now()
            ->add(new \DateInterval('PT' . max(0, $minutes) . 'M'))
            ->format('Y-m-d H:i:s');
    }
}
