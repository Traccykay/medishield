<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Security\Csrf;
use PHPUnit\Framework\TestCase;

/** Tests for CSRF token generation and timing-safe verification (spec §17). */
final class CsrfTest extends TestCase
{
    public function testGeneratesAndPersistsToken(): void
    {
        $session = [];
        $token = Csrf::token($session);

        self::assertNotSame('', $token);
        self::assertSame($token, $session[Csrf::SESSION_KEY]);
        // Asking again returns the same token (does not regenerate).
        self::assertSame($token, Csrf::token($session));
    }

    public function testCheckAcceptsMatchingToken(): void
    {
        $session = [];
        $token = Csrf::token($session);
        self::assertTrue(Csrf::check($session, $token));
    }

    public function testCheckRejectsWrongOrMissingToken(): void
    {
        $session = [];
        Csrf::token($session);

        self::assertFalse(Csrf::check($session, 'not-the-token'));
        self::assertFalse(Csrf::check($session, null));
        self::assertFalse(Csrf::check($session, ''));
        self::assertFalse(Csrf::check([], 'anything')); // no token in session
    }
}
