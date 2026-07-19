<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('pharmacy');
$prescriptions = ms_clinical_repo()->prescriptions('pending');

layout_app_header('Prescription queue', $user, 'payments');
?>
<section class="ms-card">
    <h1 class="ms-h1">Pending prescriptions</h1>
    <?php if ($prescriptions === []) { ?><p class="ms-muted">No pending prescriptions.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table">
            <thead><tr><th>Patient #</th><th>Name</th><th>Medication</th><th>Dosage</th><th>Doctor</th><th>Action</th></tr></thead>
            <tbody><?php foreach ($prescriptions as $rx) { ?><tr>
                <td><?= e((string) $rx['patient_number']) ?></td>
                <td><?= e((string) $rx['patient_name']) ?></td>
                <td><?= e(ms_clinical_service()->decrypt((string) $rx['medication_encrypted'])) ?></td>
                <td><?= e(ms_clinical_service()->decrypt((string) $rx['dosage_encrypted'])) ?></td>
                <td><?= e((string) $rx['doctor_name']) ?></td>
                <td><a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/pharmacy/dispense.php?prescription_id=' . (int) $rx['prescription_id'])) ?>">Dispense</a></td>
            </tr><?php } ?></tbody>
        </table></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
