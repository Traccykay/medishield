<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Security\PublicRuntimePolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PublicRuntimePolicyTest extends TestCase
{
    public function testDecide_WithEveryPublicPhpPage_RecognizesCurrentRouteInventory(): void
    {
        $publicRoot = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'public';
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($publicRoot, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if (
                !$file instanceof \SplFileInfo
                || !$file->isFile()
                || strtolower($file->getExtension()) !== 'php'
                || $file->getFilename() === 'router.php'
            ) {
                continue;
            }

            $relative = str_replace(
                DIRECTORY_SEPARATOR,
                '/',
                substr($file->getPathname(), strlen($publicRoot) + 1)
            );
            self::assertSame(
                ['kind' => 'route', 'status' => 200, 'path' => $relative],
                PublicRuntimePolicy::decide('/' . $relative),
                $relative . ' must be explicitly registered.'
            );
        }
    }

    public function testDecide_WithKnownRoutes_ReturnsExecutableRoute(): void
    {
        self::assertSame(
            ['kind' => 'route', 'status' => 200, 'path' => 'index.php'],
            PublicRuntimePolicy::decide('/')
        );
        self::assertSame(
            ['kind' => 'route', 'status' => 200, 'path' => 'doctor/history.php'],
            PublicRuntimePolicy::decide('/doctor/history.php?patient_id=4')
        );
    }

    public function testDecide_WithAllowlistedStylesheet_ReturnsExplicitMimeType(): void
    {
        self::assertSame(
            [
                'kind' => 'asset',
                'status' => 200,
                'path' => 'assets/css/style.css',
                'mime' => 'text/css; charset=utf-8',
            ],
            PublicRuntimePolicy::decide('/assets/css/style.css')
        );
    }

    #[DataProvider('forbiddenRequestTargets')]
    public function testDecide_WithForbiddenTarget_ReturnsControlledForbidden(string $target): void
    {
        self::assertSame(
            ['kind' => 'forbidden', 'status' => 403],
            PublicRuntimePolicy::decide($target),
            $target
        );
    }

    /**
     * @return iterable<string,array{string}>
     */
    public static function forbiddenRequestTargets(): iterable
    {
        yield 'dotfile' => ['/.htaccess'];
        yield 'nested dotfile' => ['/assets/.hidden'];
        yield 'documentation' => ['/README.md'];
        yield 'development router' => ['/router.php'];
        yield 'source map' => ['/assets/css/style.css.map'];
        yield 'backup suffix' => ['/login.php.bak'];
        yield 'dependency manifest' => ['/package.json'];
        yield 'web manifest' => ['/manifest.json'];
        yield 'source directory' => ['/src/Auth/AuthService.php'];
        yield 'configuration directory' => ['/config/config.php'];
        yield 'encoded traversal' => ['/assets/%2e%2e/router.php'];
        yield 'normalized traversal' => ['/assets/../router.php'];
        yield 'encoded separator' => ['/assets%2f..%2frouter.php'];
        yield 'double-encoded traversal' => ['/%252e%252e/router.php'];
        yield 'backslash traversal' => ['/assets%5c..%5crouter.php'];
        yield 'malformed percent encoding' => ['/assets/%ZZ/style.css'];
        yield 'control byte' => ["/assets/\x01/style.css"];
    }

    #[DataProvider('unknownRequestTargets')]
    public function testDecide_WithUnknownTarget_ReturnsControlledNotFound(string $target): void
    {
        self::assertSame(
            ['kind' => 'not_found', 'status' => 404],
            PublicRuntimePolicy::decide($target),
            $target
        );
    }

    /**
     * @return iterable<string,array{string}>
     */
    public static function unknownRequestTargets(): iterable
    {
        yield 'unknown PHP file' => ['/not-a-route.php'];
        yield 'route path info' => ['/login.php/extra'];
        yield 'asset directory' => ['/assets/css/'];
        yield 'unlisted stylesheet' => ['/assets/css/unlisted.css'];
        yield 'extensionless negotiation' => ['/login'];
    }
}
