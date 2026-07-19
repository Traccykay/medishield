<?php

declare(strict_types=1);

/**
 * layout.php
 * ----------
 * Minimal shared HTML layout helpers so every page renders the same hardened,
 * Bootstrap-styled shell without duplicating markup. Pages call:
 *
 *     layout_header('Login');
 *     ... page body ...
 *     layout_footer();
 *
 * All dynamic values passed in are escaped here with e(); pages must still escape
 * any values they echo in their own body.
 *
 * Depends on bootstrap.php (for e()) — include that first.
 */

require_once __DIR__ . '/bootstrap.php';

if (!function_exists('layout_header')) {
    /**
     * Open the HTML document and (optionally) a top navbar showing the logged-in
     * user. $user is the array returned by current_user(), or null for guest pages.
     *
     * @param array{full_name?:string,role?:string}|null $user
     */
    function layout_header(string $title, ?array $user = null): void
    {
        echo "<!doctype html>\n";
        echo "<html lang=\"en\">\n<head>\n";
        echo "<meta charset=\"utf-8\">\n";
        echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
        echo '<title>' . e($title) . " &middot; MediShield</title>\n";
        // Bootstrap from local assets keeps the demo working offline and avoids a
        // third-party origin in the Content-Security-Policy.
        echo "<link rel=\"stylesheet\" href=\"" . e(ms_url('/assets/css/style.css')) . "\">\n";
        echo "</head>\n<body>\n";

        echo "<nav class=\"ms-nav\">\n";
        echo "<div class=\"ms-nav-inner\">\n";
        echo '<a class="ms-brand" href="' . e(ms_url('/index.php')) . "\">MediShield</a>\n";
        if ($user !== null) {
            echo "<div class=\"ms-nav-user\">\n";
            echo '<span>' . e($user['full_name'] ?? '') . ' (' . e($user['role'] ?? '') . ")</span>\n";
            echo '<a class="ms-btn ms-btn-sm" href="' . e(ms_url('/logout.php')) . "\">Log out</a>\n";
            echo "</div>\n";
        }
        echo "</div>\n</nav>\n";

        echo "<main class=\"ms-main\">\n";
    }
}

if (!function_exists('layout_footer')) {
    /** Close the document opened by layout_header(). */
    function layout_footer(): void
    {
        echo "</main>\n";
        echo "<footer class=\"ms-footer\">MediShield &middot; Secure Healthcare Records</footer>\n";
        echo "</body>\n</html>\n";
    }
}

if (!function_exists('layout_alert')) {
    /**
     * Render a coloured message box. $type is one of: success, danger, warning, info.
     * The message is escaped, so it is safe to pass user-influenced text.
     */
    function layout_alert(string $type, string $message): void
    {
        $allowed = ['success', 'danger', 'warning', 'info'];
        $type = in_array($type, $allowed, true) ? $type : 'info';
        echo '<div class="ms-alert ms-alert-' . $type . '">' . e($message) . "</div>\n";
    }
}

if (!function_exists('layout_nav_items')) {
    /**
     * Presentation metadata for each sidebar nav key: its visible label and the URL
     * it points to. Authorization for these lives in Rbac (canAccessNav) — this map
     * only decides how an allowed item looks. Keeping labels/URLs here (not in Rbac)
     * preserves the split: Rbac = "who may", layout = "how it renders".
     *
     * @return array<string, array{label:string, path:string}>
     */
    function layout_nav_items(string $role): array
    {
        // Dashboard target depends on role; reuse the guard helper when available.
        $dashboard = function_exists('landing_path_for')
            ? landing_path_for($role)
            : '/dashboard.php';

        return [
            'dashboard' => ['label' => 'Dashboard',          'path' => $dashboard],
            'users'     => ['label' => 'Users',              'path' => '/admin/users.php'],
            'patients'  => ['label' => 'Patients',           'path' => '/patients.php'],
            'reports'   => ['label' => 'Reports',            'path' => '/reports.php'],
            'payments'  => ['label' => 'Payments',           'path' => '/payments.php'],
            'audit'     => ['label' => 'Forensic Auditing',  'path' => '/admin/audit.php'],
            'logout'    => ['label' => 'Logout',             'path' => '/logout.php'],
        ];
    }
}

if (!function_exists('layout_app_header')) {
    /**
     * Open an AUTHENTICATED page: full app shell with a top header and a left
     * sidebar. Use this (instead of layout_header) on every page behind a login.
     * Guest pages (login, OTP, activation, 403) keep using layout_header().
     *
     * The sidebar is built from {@see \MediShield\Auth\Rbac::navFor()} so a user
     * only sees the links their role is allowed — but remember each target page
     * must STILL enforce access server-side (require_nav/require_area). Hiding a
     * link is convenience, not security.
     *
     * @param array{full_name?:string,role?:string} $user      From current_user().
     * @param string                                $activeNav The nav key of the
     *                                                          current page, e.g.
     *                                                          'dashboard', so it is
     *                                                          highlighted.
     */
    function layout_app_header(string $title, array $user, string $activeNav = ''): void
    {
        $role  = (string) ($user['role'] ?? '');
        $items = layout_nav_items($role);

        echo "<!doctype html>\n<html lang=\"en\">\n<head>\n";
        echo "<meta charset=\"utf-8\">\n";
        echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
        echo '<title>' . e($title) . " &middot; MediShield</title>\n";
        echo "<link rel=\"stylesheet\" href=\"" . e(ms_url('/assets/css/style.css')) . "\">\n";
        echo "</head>\n<body>\n";

        echo "<div class=\"ms-shell\">\n";

        // --- Top header ---
        echo "<header class=\"ms-topbar\">\n";
        echo '<a class="ms-brand" href="' . e(ms_url($items['dashboard']['path'])) . "\">MediShield</a>\n";
        echo "<div class=\"ms-topbar-user\">\n";
        echo '<span class="ms-topbar-name">' . e($user['full_name'] ?? '')
            . ' <span class="ms-badge ms-badge-muted">' . e($role) . "</span></span>\n";
        echo '<a class="ms-btn ms-btn-sm" href="' . e(ms_url('/logout.php')) . "\">Log out</a>\n";
        echo "</div>\n</header>\n";

        // --- Body: sidebar + content ---
        echo "<div class=\"ms-body\">\n";
        echo "<nav class=\"ms-sidebar\" aria-label=\"Main navigation\">\n";
        foreach (\MediShield\Auth\Rbac::navFor($role) as $key) {
            if (!isset($items[$key])) {
                continue;
            }
            $active = ($key === $activeNav) ? ' active' : '';
            echo '<a class="ms-sidebar-link' . $active . '" href="'
                . e(ms_url($items[$key]['path'])) . '">' . e($items[$key]['label']) . "</a>\n";
        }
        echo "</nav>\n";

        echo "<main class=\"ms-content\">\n";
    }
}

if (!function_exists('layout_app_footer')) {
    /** Close the document opened by layout_app_header(). */
    function layout_app_footer(): void
    {
        echo "</main>\n";          // .ms-content
        echo "</div>\n";           // .ms-body
        echo "<footer class=\"ms-footer\">MediShield &middot; Secure Healthcare Records</footer>\n";
        echo "</div>\n";           // .ms-shell
        echo "</body>\n</html>\n";
    }
}
