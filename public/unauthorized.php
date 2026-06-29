<?php

declare(strict_types=1);

/**
 * unauthorized.php
 * ----------------
 * The 403 page shown when an authenticated user tries to reach something their
 * role may not access. The blocked attempt is audited at the point of denial
 * (see deny_access() in guard.php); this page only informs the user.
 */

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

http_response_code(403);

$user = current_user();

layout_header('Access denied', $user);
?>
<section class="ms-card">
    <h1 class="ms-h1">Access denied</h1>
    <p>You do not have permission to view that page.</p>
    <?php if ($user !== null) { ?>
        <a class="ms-btn ms-btn-primary" href="<?= e(ms_url(landing_path_for($user['role']))) ?>">Back to your dashboard</a>
    <?php } else { ?>
        <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/login.php')) ?>">Go to login</a>
    <?php } ?>
</section>
<?php
layout_footer();
