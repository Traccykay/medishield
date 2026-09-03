<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use InvalidArgumentException;
use MediShield\Support\LocalUrl;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LocalUrlTest extends TestCase
{
    public function testBuild_WithLocalTargetAndBasePath_ReturnsAppAbsolutePath(): void
    {
        self::assertSame(
            '/medishield/public/login.php?timeout=1',
            LocalUrl::build('/login.php?timeout=1', '/medishield/public')
        );
        self::assertSame('/login.php', LocalUrl::build('/login.php', ''));
    }

    public function testBuild_WithLocalFragmentAndEncodedQuery_PreservesSafeTarget(): void
    {
        self::assertSame(
            '/patients.php?q=Jane%20Doe#results',
            LocalUrl::build('/patients.php?q=Jane%20Doe#results')
        );
    }

    #[DataProvider('unsafeTargets')]
    public function testBuild_WithUnsafeTarget_ThrowsInvalidArgumentException(string $target): void
    {
        $this->expectException(InvalidArgumentException::class);
        LocalUrl::build($target);
    }

    /**
     * @return iterable<string,array{string}>
     */
    public static function unsafeTargets(): iterable
    {
        yield 'empty' => [''];
        yield 'relative' => ['login.php'];
        yield 'absolute HTTP' => ['http://attacker.example/login'];
        yield 'absolute HTTPS' => ['https://attacker.example/login'];
        yield 'scheme relative' => ['//attacker.example/login'];
        yield 'backslash authority' => ['/\\attacker.example/login'];
        yield 'raw carriage return' => ["/login.php\r\nX-Test: injected"];
        yield 'encoded carriage return' => ['/login.php%0d%0aX-Test:%20injected'];
        yield 'dot segment' => ['/admin/../login.php'];
        yield 'encoded dot segment' => ['/admin/%2e%2e/login.php'];
        yield 'encoded separator' => ['/admin%2flogin.php'];
        yield 'double encoding' => ['/%252f%252fattacker.example'];
        yield 'malformed percent encoding' => ['/login.php%'];
    }

    #[DataProvider('invalidRedirectStatuses')]
    public function testAssertRedirectStatus_WithNonRedirectStatus_ThrowsInvalidArgumentException(
        int $status
    ): void {
        $this->expectException(InvalidArgumentException::class);
        LocalUrl::assertRedirectStatus($status);
    }

    /**
     * @return iterable<string,array{int}>
     */
    public static function invalidRedirectStatuses(): iterable
    {
        yield 'success' => [200];
        yield 'forbidden' => [403];
        yield 'server error' => [500];
    }

    public function testAssertRedirectStatus_WithSupportedRedirectStatus_ReturnsStatus(): void
    {
        foreach ([301, 302, 303, 307, 308] as $status) {
            self::assertSame($status, LocalUrl::assertRedirectStatus($status));
        }
    }
}
