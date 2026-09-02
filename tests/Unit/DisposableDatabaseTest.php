<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use InvalidArgumentException;
use MediShield\Support\DisposableDatabase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DisposableDatabaseTest extends TestCase
{
    #[DataProvider('allowedNames')]
    public function testRequireUiTestName_WithApprovedDatabase_ReturnsName(string $database): void
    {
        self::assertSame($database, DisposableDatabase::requireUiTestName($database));
    }

    public function testRequireUiTestName_WithNormalApplicationDatabase_ThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('isolated UI test database');

        DisposableDatabase::requireUiTestName('medishield_db');
    }

    public function testRequireUiTestName_WithEmptyName_ThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);

        DisposableDatabase::requireUiTestName('');
    }

    /** @return array<string,array{string}> */
    public static function allowedNames(): array
    {
        return [
            'workflow database' => ['medishield_ui_test'],
            'account database' => ['medishield_ui_account_test'],
        ];
    }
}
