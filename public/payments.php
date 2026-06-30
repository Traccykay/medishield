<?php

declare(strict_types=1);

/**
 * payments.php
 * ------------
 * Placeholder for the Payments module (not yet implemented). It exists so the
 * sidebar "Payments" link resolves and so the access rules can be demonstrated.
 *
 * Authorization: require_nav('payments') enforces — server-side — that the role is
 * allowed to see Payments (admins, pharmacists and patients, per Rbac). The sidebar
 * only hides the link; this guard is the real gate. A role without access that
 * types the URL is audited and shown the 403 page.
 */

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

$user = require_nav('payments');

layout_app_header('Payments', $user, 'payments');
?>
<section class="ms-card">
    <h1 class="ms-h1">Payments</h1>
    <p class="ms-muted">Billing and payment records.</p>

    <div class="ms-alert ms-alert-info">
        This module is a placeholder. Payment features will be added in a later
        deliverable. The page is included now to demonstrate the consistent layout
        and role-based navigation.
    </div>
</section>
<?php
layout_app_footer();
