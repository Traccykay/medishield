<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Auth\Rbac;
use PHPUnit\Framework\TestCase;

/** Tests for role validation and area access rules (spec §6, §7). */
final class RbacTest extends TestCase
{
    public function testRecognisesAllSixRoles(): void
    {
        foreach (['patient', 'nurse', 'doctor', 'lab', 'pharmacist', 'admin'] as $role) {
            self::assertTrue(Rbac::isValidRole($role), "$role should be valid");
        }
        self::assertFalse(Rbac::isValidRole('superuser'));
        self::assertFalse(Rbac::isValidRole(''));
    }

    public function testOnlyAdminCanAccessAdminArea(): void
    {
        self::assertTrue(Rbac::canAccessArea('admin', 'admin'));
        self::assertFalse(Rbac::canAccessArea('nurse', 'admin'));
        self::assertFalse(Rbac::canAccessArea('doctor', 'admin'));
        self::assertFalse(Rbac::canAccessArea('patient', 'admin'));
    }

    public function testEachRoleAccessesOnlyItsOwnArea(): void
    {
        self::assertTrue(Rbac::canAccessArea('nurse', 'nurse'));
        self::assertTrue(Rbac::canAccessArea('doctor', 'doctor'));
        self::assertTrue(Rbac::canAccessArea('lab', 'lab'));
        self::assertTrue(Rbac::canAccessArea('pharmacist', 'pharmacy'));
        self::assertFalse(Rbac::canAccessArea('lab', 'pharmacy'));
    }

    public function testOnlyAdminCanManageUsers(): void
    {
        self::assertTrue(Rbac::canManageUsers('admin'));
        self::assertFalse(Rbac::canManageUsers('doctor'));
    }

    public function testDashboardPathPerRole(): void
    {
        self::assertSame('/admin/dashboard.php', Rbac::dashboardPath('admin'));
        self::assertSame('/patient/dashboard.php', Rbac::dashboardPath('patient'));
        self::assertSame('/login.php', Rbac::dashboardPath('unknown'));
    }
}
