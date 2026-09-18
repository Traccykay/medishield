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

use MediShield\Security\Csrf;

require_once __DIR__ . '/bootstrap.php';

if (!function_exists('layout_stylesheet_url')) {
    /**
     * Return a same-origin stylesheet URL whose version follows the file mtime.
     * This prevents browsers from pairing new layout markup with stale CSS.
     */
    function layout_stylesheet_url(): string
    {
        $stylesheet = __DIR__ . '/../public/assets/css/style.css';
        $modifiedAt = is_file($stylesheet) ? filemtime($stylesheet) : false;
        $version = $modifiedAt === false ? '1' : (string) $modifiedAt;

        return ms_url('/assets/css/style.css?v=' . rawurlencode($version));
    }
}

if (!function_exists('layout_logout_form')) {
    /** Render a CSRF-protected logout action without exposing logout as a GET link. */
    function layout_logout_form(
        string $label = 'Log out',
        string $formClass = 'ms-inline-form',
        string $buttonClass = 'ms-btn ms-btn-sm'
    ): void {
        $token = Csrf::token($_SESSION);
        echo '<form method="post" action="' . e(ms_url('/logout.php')) . '" class="' . e($formClass) . "\">\n";
        echo '<input type="hidden" name="' . e(Csrf::FIELD) . '" value="' . e($token) . "\">\n";
        echo '<button type="submit" class="' . e($buttonClass) . '">' . e($label) . "</button>\n";
        echo "</form>\n";
    }
}

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
        echo "<link rel=\"stylesheet\" href=\"" . e(layout_stylesheet_url()) . "\">\n";
        echo "</head>\n<body>\n";
        echo '<a class="ms-skip-link" href="#main-content">Skip to main content</a>' . "\n";

        echo "<nav class=\"ms-nav\">\n";
        echo "<div class=\"ms-nav-inner\">\n";
        echo '<a class="ms-brand" href="' . e(ms_url('/index.php')) . "\">MediShield</a>\n";
        if ($user !== null) {
            echo "<div class=\"ms-nav-user\">\n";
            echo '<span>' . e($user['full_name'] ?? '') . ' (' . e($user['role'] ?? '') . ")</span>\n";
            layout_logout_form();
            echo "</div>\n";
        }
        echo "</div>\n</nav>\n";

        echo "<main class=\"ms-main\" id=\"main-content\" tabindex=\"-1\">\n";
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

if (!function_exists('layout_access_denied')) {
    /** Render the controlled denial at the original URL without redirecting it. */
    function layout_access_denied(?array $user): never
    {
        http_response_code(403);
        layout_header('Access denied', $user);
        echo "<section class=\"ms-card\">\n";
        echo "<h1 class=\"ms-h1\">Access denied</h1>\n";
        echo "<p>You do not have permission to view that page.</p>\n";
        $target = $user !== null
            ? landing_path_for((string) ($user['role'] ?? ''))
            : '/login.php';
        $label = $user !== null ? 'Back to your dashboard' : 'Go to login';
        echo '<a class="ms-btn ms-btn-primary" href="' . e(ms_url($target)) . '">'
            . e($label) . "</a>\n";
        echo "</section>\n";
        layout_footer();
        exit;
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
        $role = $type === 'danger' ? 'alert' : 'status';
        $live = $type === 'danger' ? 'assertive' : 'polite';
        echo '<div class="ms-alert ms-alert-' . $type . '" role="' . $role
            . '" aria-live="' . $live . '" aria-atomic="true">' . e($message) . "</div>\n";
    }
}

if (!function_exists('layout_patient_context')) {
    /**
     * Render only the already-authorized identity and visit metadata supplied by
     * the calling controller. This helper performs no lookup or authorization.
     *
     * @param array<string,mixed> $patient
     * @param array<string,mixed> $visit
     */
    function layout_patient_context(array $patient, array $visit): void
    {
        $name = (string) ($patient['full_name'] ?? $patient['patient_name'] ?? 'Patient');
        $number = (string) ($patient['patient_number'] ?? $visit['patient_number'] ?? '');
        $visitId = (int) ($visit['visit_id'] ?? 0);
        $status = (string) ($visit['status'] ?? '');

        echo '<section class="ms-patient-context" aria-label="Current patient and visit">' . "\n";
        echo '<div class="ms-patient-identity"><div><p class="ms-dashboard-kicker">Current encounter</p>';
        echo '<p class="ms-patient-name">' . e($name) . '</p></div><div class="ms-patient-meta">';
        if ($number !== '') {
            echo '<span>' . e($number) . '</span>';
        }
        if ($visitId > 0) {
            echo '<span>Visit #' . e((string) $visitId) . '</span>';
        }
        echo "</div></div>\n";
        echo '<ol class="ms-visit-progress" aria-label="Visit progress">';
        foreach (\MediShield\Visit\VisitProgress::stages($status) as $stage) {
            echo '<li class="ms-visit-step ms-visit-step-' . e($stage['state']) . '"';
            if ($stage['state'] === 'current') {
                echo ' aria-current="step"';
            }
            echo '><span class="ms-visit-dot" aria-hidden="true"></span><span>' . e($stage['label']) . '</span></li>';
        }
        echo "</ol>\n</section>\n";
    }
}

if (!function_exists('layout_pagination')) {
    /** @param array{total:int,page:int,page_count:int,per_page:int} $pageData @param array<string,string|int> $params */
    function layout_pagination(array $pageData, string $path, array $params = []): void
    {
        echo '<nav class="ms-pagination" aria-label="List pages"><span>Page '
            . e((string) $pageData['page']) . ' of ' . e((string) $pageData['page_count'])
            . ' · ' . e((string) $pageData['total']) . " results</span><span class=\"ms-actions\">";
        foreach (['Previous' => $pageData['page'] - 1, 'Next' => $pageData['page'] + 1] as $label => $target) {
            $allowed = $label === 'Previous' ? $pageData['page'] > 1 : $pageData['page'] < $pageData['page_count'];
            if ($allowed) {
                $query = http_build_query(array_merge($params, ['page' => $target, 'per_page' => $pageData['per_page']]));
                echo '<a class="ms-btn ms-btn-sm" href="' . e(ms_url($path . '?' . $query)) . '">' . e($label) . '</a>';
            }
        }
        echo "</span></nav>\n";
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
            'reception'=> ['label' => 'Reception',           'path' => '/reception/dashboard.php'],
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
        echo "<link rel=\"stylesheet\" href=\"" . e(layout_stylesheet_url()) . "\">\n";
        echo "</head>\n<body>\n";
        echo '<a class="ms-skip-link" href="#main-content">Skip to main content</a>' . "\n";

        echo "<div class=\"ms-shell\">\n";

        // --- Top header ---
        echo "<header class=\"ms-topbar\">\n";
        echo '<a class="ms-brand" href="' . e(ms_url($items['dashboard']['path']))
            . '" aria-label="MediShield dashboard"><span class="ms-brand-mark" aria-hidden="true">M</span>'
            . '<span>MediShield</span></a>' . "\n";
        echo "<div class=\"ms-topbar-user\">\n";
        echo '<span class="ms-topbar-name">' . e($user['full_name'] ?? '')
            . ' <span class="ms-badge ms-badge-muted">' . e($role) . "</span></span>\n";
        layout_logout_form();
        echo "</div>\n</header>\n";

        // --- Body: sidebar + content ---
        echo "<div class=\"ms-body\">\n";
        echo "<nav class=\"ms-sidebar\" aria-label=\"Main navigation\">\n";
        echo '<span class="ms-sidebar-label">Workspace</span>' . "\n";
        foreach (\MediShield\Auth\Rbac::navFor($role) as $key) {
            if (!isset($items[$key])) {
                continue;
            }
            if ($key === 'logout') {
                layout_logout_form(
                    $items[$key]['label'],
                    'ms-sidebar-form',
                    'ms-sidebar-link ms-sidebar-button'
                );
                continue;
            }
            $active = ($key === $activeNav) ? ' active' : '';
            $current = $key === $activeNav ? ' aria-current="page"' : '';
            echo '<a class="ms-sidebar-link' . $active . '"' . $current . ' href="'
                . e(ms_url($items[$key]['path'])) . '"><span>'
                . e($items[$key]['label']) . "</span></a>\n";
        }
        echo "</nav>\n";

        echo "<main class=\"ms-content\" id=\"main-content\" tabindex=\"-1\">\n";
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
