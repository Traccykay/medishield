<?php

declare(strict_types=1);

namespace MediShield\Auth;

/**
 * Rbac
 * ----
 * Role-Based Access Control helpers (spec §6, §7, §15).
 *
 * MediShield has exactly six roles and each user has exactly one of them. This
 * class answers two questions the application asks on every request:
 *   1. Is this a valid role string?
 *   2. May a user with role X enter area Y (e.g. the "admin" area)?
 *
 * "Areas" map to the URL sections under public/ (admin/, doctor/, nurse/, ...).
 * The actual page guards (require_login/require_role) live in includes/guard.php
 * and call into here; record-level ("is this patient assigned to me?") checks are
 * handled separately because they need the database.
 */
final class Rbac
{
    public const ROLE_PATIENT    = 'patient';
    public const ROLE_NURSE      = 'nurse';
    public const ROLE_DOCTOR     = 'doctor';
    public const ROLE_LAB        = 'lab';
    public const ROLE_PHARMACIST = 'pharmacist';
    public const ROLE_ADMIN      = 'admin';

    /** The complete, ordered list of valid roles. */
    public const ROLES = [
        self::ROLE_PATIENT,
        self::ROLE_NURSE,
        self::ROLE_DOCTOR,
        self::ROLE_LAB,
        self::ROLE_PHARMACIST,
        self::ROLE_ADMIN,
    ];

    /**
     * Which roles may access each URL area. Areas correspond to folders in public/.
     *
     * @var array<string, string[]>
     */
    private const AREA_ROLES = [
        'admin'    => [self::ROLE_ADMIN],
        'patient'  => [self::ROLE_PATIENT],
        'nurse'    => [self::ROLE_NURSE],
        'doctor'   => [self::ROLE_DOCTOR],
        'lab'      => [self::ROLE_LAB],
        'pharmacy' => [self::ROLE_PHARMACIST],
    ];

    /** True if $role is one of the six recognised roles. */
    public static function isValidRole(string $role): bool
    {
        return in_array($role, self::ROLES, true);
    }

    /** True if a user with $role may enter the given URL $area (e.g. 'admin'). */
    public static function canAccessArea(string $role, string $area): bool
    {
        $allowed = self::AREA_ROLES[$area] ?? [];
        return in_array($role, $allowed, true);
    }

    /** Only administrators may create/manage users (spec §9.2). */
    public static function canManageUsers(string $role): bool
    {
        return $role === self::ROLE_ADMIN;
    }

    /** Convenience: the dashboard landing path for a role, used after login. */
    public static function dashboardPath(string $role): string
    {
        return match ($role) {
            self::ROLE_ADMIN      => '/admin/dashboard.php',
            self::ROLE_PATIENT    => '/patient/dashboard.php',
            self::ROLE_NURSE      => '/nurse/dashboard.php',
            self::ROLE_DOCTOR     => '/doctor/dashboard.php',
            self::ROLE_LAB        => '/lab/dashboard.php',
            self::ROLE_PHARMACIST => '/pharmacy/dashboard.php',
            default               => '/login.php',
        };
    }
}
