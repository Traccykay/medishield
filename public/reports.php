<?php

declare(strict_types=1);

/**
 * reports.php
 * -----------
 * Placeholder for the Reports module (not yet implemented). It exists so the
 * sidebar "Reports" link resolves and so the access rules can be demonstrated.
 *
 * Authorization: require_nav('reports') enforces — server-side — that the role is
 * actually allowed to see Reports (everyone except patients, per Rbac). This is the
 * real gate; the sidebar only hides the link. A patient who types this URL is
 * audited and shown the 403 page.
 */

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

$user = require_nav('reports');

layout_app_header('Reports', $user, 'reports');
?>
<section class="ms-card">
    <h1 class="ms-h1">Reports</h1>
    <p class="ms-muted">Operational and clinical reporting.</p>

    <div class="ms-alert ms-alert-info">
        This module is a placeholder. Reporting features will be added in a later
        deliverable. The page is included now to demonstrate the consistent layout
        and role-based navigation.
    </div>
</section>
<?php
layout_app_footer();
