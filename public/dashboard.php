<?php

declare(strict_types=1);

/**
 * dashboard.php
 * -------------
 * The generic landing page for every NON-admin role in Deliverable 1.
 *
 * Deliverable 1 only builds the authentication + admin user-management slice, so
 * the clinical workspaces (patient, nurse, doctor, lab, pharmacist) do not exist
 * yet. guard.php's landing_path_for() sends those roles here so a successful
 * login never lands on a 404. Later deliverables will replace this with each
 * role's real dashboard (see Rbac::dashboardPath()).
 *
 * It is still a fully protected page: require_login() enforces authentication,
 * session timeout, and the forced-password-change redirect.
 */

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

$user = require_login();

layout_header('Dashboard', $user);
?>
<section class="ms-card">
    <h1 class="ms-h1">Welcome, <?= e($user['full_name']) ?></h1>
    <p class="ms-muted">Signed in as <strong><?= e($user['role']) ?></strong> (<?= e($user['email']) ?>).</p>

    <div class="ms-alert ms-alert-info">
        Your role workspace is coming in a later deliverable. Deliverable&nbsp;1 covers
        secure authentication and administrator user management.
    </div>

    <ul class="ms-list">
        <li><a href="/change_password.php">Change my password</a></li>
        <li><a href="/logout.php">Log out</a></li>
    </ul>
</section>
<?php
layout_footer();
