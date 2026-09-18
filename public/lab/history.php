<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('lab');
$requests = ms_clinical_repo()->completedByLabTechnician((int) $user['user_id']);
ms_audit_read($user, 'lab.history', array_column($requests, 'patient_id'));
layout_app_header('Completed tests', $user, 'reports');
?>
<section class="ms-card"><h1 class="ms-h1">Completed test history</h1>
<?php if ($requests === []) { ?><p class="ms-muted">No completed tests.</p><?php } else { ?>
<div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Test</th><th>Patient</th><th>Doctor</th><th>Completed</th></tr></thead><tbody>
<?php foreach ($requests as $request) { ?><tr><td><?= e((string) $request['test_name']) ?></td><td><?= e((string) $request['patient_name']) ?></td><td><?= e((string) $request['doctor_name']) ?></td><td><?= e((string) $request['created_at']) ?></td></tr><?php } ?>
</tbody></table></div><?php } ?>
</section>
<?php layout_app_footer(); ?>
