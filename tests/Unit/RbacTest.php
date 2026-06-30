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

    public function testEveryRoleSeesDashboardAndLogoutNav(): void
    {
        foreach (Rbac::ROLES as $role) {
            self::assertTrue(Rbac::canAccessNav($role, 'dashboard'), "$role should see dashboard");
            self::assertTrue(Rbac::canAccessNav($role, 'logout'), "$role should see logout");
        }
    }

    public function testOnlyAdminSeesUsersAndAuditNav(): void
    {
        self::assertTrue(Rbac::canAccessNav('admin', 'users'));
        self::assertTrue(Rbac::canAccessNav('admin', 'audit'));
        foreach (['patient', 'nurse', 'doctor', 'lab', 'pharmacist'] as $role) {
            self::assertFalse(Rbac::canAccessNav($role, 'users'), "$role must not see users");
            self::assertFalse(Rbac::canAccessNav($role, 'audit'), "$role must not see audit");
        }
    }

    public function testPatientCannotSeeReports(): void
    {
        self::assertFalse(Rbac::canAccessNav('patient', 'reports'));
        self::assertTrue(Rbac::canAccessNav('doctor', 'reports'));
        self::assertTrue(Rbac::canAccessNav('admin', 'reports'));
    }

    public function testUnknownNavKeyIsDenied(): void
    {
        self::assertFalse(Rbac::canAccessNav('admin', 'nonexistent-nav'));
    }

    public function testNavForReturnsOrderedAllowedKeys(): void
    {
        $adminNav = Rbac::navFor('admin');
        self::assertContains('dashboard', $adminNav);
        self::assertContains('users', $adminNav);
        self::assertContains('audit', $adminNav);
        self::assertContains('logout', $adminNav);
        // Dashboard always comes first, logout always last.
        self::assertSame('dashboard', $adminNav[0]);
        self::assertSame('logout', $adminNav[array_key_last($adminNav)]);

        // A nurse never gets admin-only items.
        $nurseNav = Rbac::navFor('nurse');
        self::assertNotContains('users', $nurseNav);
        self::assertNotContains('audit', $nurseNav);
    }
}
