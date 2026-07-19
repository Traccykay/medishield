<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('pharmacy');
$prescriptions = ms_clinical_repo()->prescriptions('dispensed');
layout_app_header('Dispensed medication', $user, 'payments');
?>
<section class="ms-card"><h1 class="ms-h1">Dispensed medication history</h1>
<?php if ($prescriptions === []) { ?><p class="ms-muted">No dispensed medication.</p><?php } else { ?>
<div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Patient</th><th>Medication</th><th>Doctor</th><th>Issued</th></tr></thead><tbody>
<?php foreach ($prescriptions as $rx) { ?><tr><td><?= e((string) $rx['patient_name']) ?></td><td><?= e(ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? '') ?></td><td><?= e((string) $rx['doctor_name']) ?></td><td><?= e((string) $rx['created_at']) ?></td></tr><?php } ?>
</tbody></table></div><?php } ?>
</section>
<?php layout_app_footer(); ?>
