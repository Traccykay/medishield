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
        echo "<link rel=\"stylesheet\" href=\"/assets/css/style.css\">\n";
        echo "</head>\n<body>\n";

        echo "<nav class=\"ms-nav\">\n";
        echo "<div class=\"ms-nav-inner\">\n";
        echo "<a class=\"ms-brand\" href=\"/index.php\">MediShield</a>\n";
        if ($user !== null) {
            echo "<div class=\"ms-nav-user\">\n";
            echo '<span>' . e($user['full_name'] ?? '') . ' (' . e($user['role'] ?? '') . ")</span>\n";
            echo "<a class=\"ms-btn ms-btn-sm\" href=\"/logout.php\">Log out</a>\n";
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
