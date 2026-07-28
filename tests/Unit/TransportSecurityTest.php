<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Security\TransportSecurity;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the trusted-proxy boundary used to require HTTPS in production.
 */
final class TransportSecurityTest extends TestCase
{
    public function testIsHttps_ReturnsTrueForDirectHttps(): void
    {
        self::assertTrue(TransportSecurity::isHttps(['HTTPS' => 'on']));
    }

    public function testIsHttps_RejectsSpoofedForwardedHeaderFromPublicClient(): void
    {
        self::assertFalse(TransportSecurity::isHttps([
            'REMOTE_ADDR' => '203.0.113.14',
            'HTTP_X_FORWARDED_PROTO' => 'https',
        ], ['127.0.0.1']));
    }

    public function testIsHttps_AcceptsForwardedHttpsOnlyFromConfiguredProxy(): void
    {
        self::assertTrue(TransportSecurity::isHttps([
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_PROTO' => 'https',
        ], ['127.0.0.1']));
    }

    public function testIsHttps_RejectsAmbiguousForwardedProtocol(): void
    {
        self::assertFalse(TransportSecurity::isHttps([
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_PROTO' => 'http, https',
        ], ['127.0.0.1']));
    }
}
