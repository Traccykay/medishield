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

    /**
     * Sidebar navigation visibility (spec §6, §7). This is PRESENTATION-level
     * filtering — it decides which links a role sees in the sidebar. It is NOT a
     * substitute for the server-side page guards: every page must still enforce its
     * own access with require_login/require_role/require_nav. Hiding a link only
     * declutters the UI; it never grants or denies real authorization.
     *
     * Nav keys are abstract (not URLs) so the layout owns the labels/hrefs while
     * authorization stays here. Order matters: it is the order links render in.
     *
     * @var array<string, string[]>
     */
    private const NAV_ROLES = [
        // Everyone who is logged in has a dashboard and can log out.
        'dashboard' => self::ROLES,
        'logout'    => self::ROLES,
        // Admin-only management + security surfaces.
        'users'     => [self::ROLE_ADMIN],
        'audit'     => [self::ROLE_ADMIN],
        // Clinical/operational staff (everyone except patients) see reports.
        'reports'   => [
            self::ROLE_ADMIN,
            self::ROLE_NURSE,
            self::ROLE_DOCTOR,
            self::ROLE_LAB,
            self::ROLE_PHARMACIST,
        ],
        // Billing surfaces: admins, the dispensing pharmacist, and patients.
        'payments'  => [
            self::ROLE_ADMIN,
            self::ROLE_PHARMACIST,
            self::ROLE_PATIENT,
        ],
    ];

    /**
     * Render order of the sidebar. dashboard first, logout last; everything else in
     * between. {@see navFor()} returns this list filtered to a role.
     *
     * @var string[]
     */
    private const NAV_ORDER = ['dashboard', 'users', 'reports', 'payments', 'audit', 'logout'];

    /** True if a role may see/use the given sidebar nav key. */
    public static function canAccessNav(string $role, string $navKey): bool
    {
        $allowed = self::NAV_ROLES[$navKey] ?? [];
        return in_array($role, $allowed, true);
    }

    /**
     * The ordered list of nav keys a role is allowed to see, for building the
     * sidebar. Always starts with 'dashboard' and ends with 'logout'.
     *
     * @return string[]
     */
    public static function navFor(string $role): array
    {
        return array_values(array_filter(
            self::NAV_ORDER,
            static fn (string $navKey): bool => self::canAccessNav($role, $navKey)
        ));
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
