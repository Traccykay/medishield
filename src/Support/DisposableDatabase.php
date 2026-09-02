<?php

declare(strict_types=1);

namespace MediShield\Support;

use InvalidArgumentException;

/**
 * Defines databases that destructive browser-test setup and seeds may target.
 */
final class DisposableDatabase
{
    /** @var list<string> */
    private const UI_TEST_NAMES = [
        'medishield_ui_test',
        'medishield_ui_account_test',
    ];

    public static function requireUiTestName(string $database): string
    {
        if (!in_array($database, self::UI_TEST_NAMES, true)) {
            throw new InvalidArgumentException(
                'UI test setup and seeds may only target an isolated UI test database.'
            );
        }

        return $database;
    }

    public static function requireSetupTarget(string $configuredDatabase, string $selectedDatabase): string
    {
        if ($selectedDatabase === $configuredDatabase) {
            return $selectedDatabase;
        }

        try {
            return self::requireUiTestName($selectedDatabase);
        } catch (InvalidArgumentException) {
            throw new InvalidArgumentException(
                'Database setup may only target the configured database or an isolated UI test database.'
            );
        }
    }
}
