<?php

declare(strict_types=1);

namespace MediShield\Tests\Integration;

use MediShield\Security\RequestThrottle;
use MediShield\Support\Clock;
use MediShield\Tests\Support\TestSchema;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests for IP-scoped request throttling. They use the production
 * PDO implementation against SQLite so time windows and persisted scope state
 * are exercised without a live MySQL server.
 */
final class RequestThrottleTest extends TestCase
{
    public function testConstructor_WithShortKey_RejectsConfiguration(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        self::assertInstanceOf(
            RequestThrottle::class,
            new RequestThrottle(TestSchema::pdo(), new Clock(), str_repeat('ab', 31))
        );
    }

    private \DateTimeImmutable $now;
    private RequestThrottle $throttle;
    private \PDO $pdo;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-07-24 06:00:00', new \DateTimeZone('UTC'));
        $this->pdo = TestSchema::pdo();
        $this->throttle = new RequestThrottle(
            $this->pdo,
            new Clock(fn (): \DateTimeImmutable => $this->now),
            str_repeat('ab', 32)
        );
    }

    public function testAllow_AllowsRequestsUpToConfiguredLimit(): void
    {
        self::assertTrue($this->throttle->allow('login', '203.0.113.14', 2, 900));
        self::assertTrue($this->throttle->allow('login', '203.0.113.14', 2, 900));
        self::assertFalse($this->throttle->allow('login', '203.0.113.14', 2, 900));
    }

    public function testAllow_IsolatesActionsAndClientAddresses(): void
    {
        self::assertTrue($this->throttle->allow('login', '203.0.113.14', 1, 900));

        self::assertTrue($this->throttle->allow('password_reset', '203.0.113.14', 1, 900));
        self::assertTrue($this->throttle->allow('login', '203.0.113.15', 1, 900));
    }

    public function testAllow_ReopensScopeAfterWindowExpires(): void
    {
        self::assertTrue($this->throttle->allow('login', '203.0.113.14', 1, 900));
        self::assertFalse($this->throttle->allow('login', '203.0.113.14', 1, 900));

        $this->now = $this->now->add(new \DateInterval('PT15M'));

        self::assertTrue($this->throttle->allow('login', '203.0.113.14', 1, 900));
    }

    public function testAllow_StoresNoRawClientAddress(): void
    {
        $this->throttle->allow('login', '203.0.113.14', 1, 900);

        $row = $this->pdo->query('SELECT scope_hash FROM request_throttles')->fetch();

        self::assertNotSame('203.0.113.14', $row['scope_hash']);
        self::assertSame(64, strlen($row['scope_hash']));
    }

    public function testAllow_RejectsInvalidPolicyValues(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->throttle->allow('login', '203.0.113.14', 0, 900);
    }
}
