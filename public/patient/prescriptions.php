<?php

declare(strict_types=1);

use MediShield\Clinical\ClinicalCatalog;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('patient');
$patientId = ms_patient_service()->patientIdForUser((int) $user['user_id']);
if ($patientId === null) {
    redirect('/patient/dashboard.php');
}
$pending = ms_clinical_repo()->prescriptions('pending', null, $patientId);
$dispensed = ms_clinical_repo()->prescriptions('dispensed', null, $patientId);
$history = ms_clinical_repo()->dispensingForPatient($patientId);

layout_app_header('My prescriptions', $user, 'payments');
?>
<section class="ms-card">
    <h1 class="ms-h1">My prescriptions</h1>
    <?php foreach (['Pending' => $pending, 'Dispensed' => $dispensed] as $label => $rows) { ?>
        <h2 class="ms-h2"><?= e($label) ?></h2>
        <?php if ($rows === []) { ?><p class="ms-muted">No <?= e(mb_strtolower($label)) ?> prescriptions.</p><?php } else { ?>
            <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Medication</th><th>Cost</th><th>Dosage</th><th>Instructions</th><th>Doctor</th><th>UTC</th></tr></thead><tbody>
            <?php foreach ($rows as $rx) { $medication = ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? ''; ?><tr><td><?= e($medication) ?></td><td>KES <?= e(number_format(ClinicalCatalog::priceForMedication($medication) ?? 0)) ?></td><td><?= e(ms_clinical_service()->decrypt((string) $rx['dosage_encrypted'])) ?></td><td><?= e(ms_clinical_service()->decrypt($rx['instructions_encrypted'] ?? null) ?? '') ?></td><td><?= e((string) $rx['doctor_name']) ?></td><td><?= e((string) $rx['created_at']) ?></td></tr><?php } ?>
            </tbody></table></div>
        <?php } ?>
    <?php } ?>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Dispensing history</h2>
    <?php if ($history === []) { ?><p class="ms-muted">No dispensing history.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Status</th><th>Remarks</th><th>Pharmacist</th><th>UTC</th></tr></thead><tbody>
        <?php foreach ($history as $row) { ?><tr><td><?= e((string) $row['status']) ?></td><td><?= e((string) ($row['remarks'] ?? '')) ?></td><td><?= e((string) $row['pharmacist_name']) ?></td><td><?= e((string) $row['created_at']) ?></td></tr><?php } ?>
        </tbody></table></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
