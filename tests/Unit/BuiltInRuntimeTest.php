<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Real HTTP regression tests for the PHP development-server routing boundary.
 */
final class BuiltInRuntimeTest extends TestCase
{
    /** @var resource|null */
    private static $server = null;

    /** @var array<int,resource> */
    private static array $pipes = [];

    private static int $port;

    public static function setUpBeforeClass(): void
    {
        self::$port = self::reservePort();
        $root = dirname(__DIR__, 2);
        $public = $root . DIRECTORY_SEPARATOR . 'public';
        $router = $public . DIRECTORY_SEPARATOR . 'router.php';
        self::$server = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . self::$port, '-t', $public, $router],
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            self::$pipes,
            $root,
            null,
            ['bypass_shell' => true]
        );
        self::assertIsResource(self::$server);

        $ready = false;
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $socket = @fsockopen('127.0.0.1', self::$port, $errorCode, $errorMessage, 0.1);
            if (is_resource($socket)) {
                fclose($socket);
                $ready = true;
                break;
            }
            usleep(100_000);
        }
        self::assertTrue($ready, 'PHP development server did not become ready.');
    }

    public static function tearDownAfterClass(): void
    {
        foreach (self::$pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
        if (is_resource(self::$server)) {
            proc_terminate(self::$server);
            proc_close(self::$server);
        }
    }

    public function testKnownDynamicRoute_ExecutesWithUniqueSecurityAndPrivateNoStoreHeaders(): void
    {
        $response = self::request('/login.php');

        self::assertSame(200, $response['status']);
        self::assertStringContainsString('Sign in', $response['body']);
        self::assertHeader($response, 'referrer-policy', 'no-referrer');
        self::assertHeader($response, 'x-content-type-options', 'nosniff');
        self::assertHeaderContains($response, 'cache-control', 'no-store');
        self::assertHeaderContains($response, 'cache-control', 'private');
        self::assertHeaderCount($response, 'referrer-policy', 1);
        self::assertHeaderCount($response, 'content-security-policy', 1);
        self::assertArrayNotHasKey('x-powered-by', $response['headers']);
    }

    public function testAllowlistedStylesheet_HasExplicitMimeCachingAndApplicableCss(): void
    {
        $response = self::request('/assets/css/style.css');

        self::assertSame(200, $response['status']);
        self::assertHeader($response, 'content-type', 'text/css; charset=utf-8');
        self::assertHeader($response, 'x-content-type-options', 'nosniff');
        self::assertHeaderContains($response, 'cache-control', 'public');
        self::assertStringNotContainsString('no-store', self::firstHeader($response, 'cache-control'));
        self::assertStringContainsString('body {', $response['body']);
        self::assertStringContainsString('margin: 0;', $response['body']);
    }

    #[DataProvider('forbiddenRuntimeTargets')]
    public function testForbiddenTarget_ReturnsControlled403WithSecurityHeaders(string $target): void
    {
        $response = self::request($target);

        self::assertSame(403, $response['status'], $target);
        self::assertSame("Forbidden.\n", $response['body'], $target);
        self::assertHeader($response, 'referrer-policy', 'no-referrer');
        self::assertHeader($response, 'x-content-type-options', 'nosniff');
        self::assertHeaderContains($response, 'cache-control', 'no-store');
        self::assertStringNotContainsStringIgnoringCase('Stack trace', $response['body']);
        self::assertStringNotContainsString('C:\\', $response['body']);
    }

    /**
     * @return iterable<string,array{string}>
     */
    public static function forbiddenRuntimeTargets(): iterable
    {
        yield 'README' => ['/README.md'];
        yield 'dotfile' => ['/.htaccess'];
        yield 'router' => ['/router.php'];
        yield 'asset documentation' => ['/assets/README.md'];
        yield 'source map' => ['/assets/css/style.css.map'];
        yield 'backup' => ['/login.php.bak'];
        yield 'manifest' => ['/manifest.json'];
        yield 'source path' => ['/src/Auth/AuthService.php'];
        yield 'config path' => ['/config/config.php'];
        yield 'normalized traversal' => ['/assets/../router.php'];
        yield 'encoded traversal' => ['/assets/%2e%2e/router.php'];
        yield 'double encoded traversal' => ['/%252e%252e/router.php'];
    }

    public function testUnknownAndDirectoryTargets_ReturnControlled404WithoutListing(): void
    {
        foreach (['/not-a-route.php', '/login', '/assets/css/'] as $target) {
            $response = self::request($target);
            self::assertSame(404, $response['status'], $target);
            self::assertSame("Not found.\n", $response['body'], $target);
            self::assertHeader($response, 'referrer-policy', 'no-referrer');
            self::assertStringNotContainsString('style.css', $response['body']);
            self::assertStringNotContainsString('Directory listing', $response['body']);
        }
    }

    public function testTraceRequest_IsRejectedWithCoreSecurityHeaders(): void
    {
        $response = self::request('/login.php', 'TRACE');

        self::assertSame(405, $response['status']);
        self::assertHeader($response, 'referrer-policy', 'no-referrer');
        self::assertHeader($response, 'x-content-type-options', 'nosniff');
    }

    /**
     * @return array{status:int,headers:array<string,list<string>>,body:string}
     */
    private static function request(string $target, string $method = 'GET'): array
    {
        $socket = fsockopen('127.0.0.1', self::$port, $errorCode, $errorMessage, 2);
        self::assertIsResource($socket, "HTTP connection failed: {$errorCode} {$errorMessage}");
        fwrite(
            $socket,
            "{$method} {$target} HTTP/1.1\r\n"
            . "Host: 127.0.0.1:" . self::$port . "\r\n"
            . "Connection: close\r\n\r\n"
        );
        $raw = (string) stream_get_contents($socket);
        fclose($socket);

        [$head, $body] = array_pad(preg_split("/\r?\n\r?\n/", $raw, 2) ?: [], 2, '');
        $lines = preg_split("/\r?\n/", $head) ?: [];
        $statusLine = array_shift($lines);
        self::assertIsString($statusLine);
        self::assertMatchesRegularExpression('/^HTTP\/\d\.\d (?<status>\d{3})\b/', $statusLine);
        preg_match('/^HTTP\/\d\.\d (?<status>\d{3})\b/', $statusLine, $match);

        $headers = [];
        foreach ($lines as $line) {
            if (!str_contains($line, ':')) {
                continue;
            }
            [$name, $value] = explode(':', $line, 2);
            $headers[strtolower(trim($name))][] = trim($value);
        }

        return [
            'status' => (int) $match['status'],
            'headers' => $headers,
            'body' => $body,
        ];
    }

    private static function reservePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
        self::assertIsResource($socket, "Port reservation failed: {$errorCode} {$errorMessage}");
        $address = stream_socket_get_name($socket, false);
        fclose($socket);
        self::assertIsString($address);

        return (int) substr(strrchr($address, ':'), 1);
    }

    /**
     * @param array{headers:array<string,list<string>>} $response
     */
    private static function assertHeader(array $response, string $name, string $expected): void
    {
        self::assertSame($expected, self::firstHeader($response, $name), $name);
    }

    /**
     * @param array{headers:array<string,list<string>>} $response
     */
    private static function assertHeaderContains(array $response, string $name, string $expected): void
    {
        self::assertStringContainsString($expected, self::firstHeader($response, $name), $name);
    }

    /**
     * @param array{headers:array<string,list<string>>} $response
     */
    private static function assertHeaderCount(array $response, string $name, int $expected): void
    {
        self::assertCount($expected, $response['headers'][$name] ?? [], $name);
    }

    /**
     * @param array{headers:array<string,list<string>>} $response
     */
    private static function firstHeader(array $response, string $name): string
    {
        self::assertArrayHasKey($name, $response['headers']);
        return $response['headers'][$name][0];
    }
}
