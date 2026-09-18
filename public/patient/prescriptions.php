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
ms_audit_read_event([
    'user_id' => (int) $user['user_id'],
    'user_role' => 'patient',
    'action' => 'PATIENT_VIEW',
    'module' => 'patient_prescriptions',
    'affected_record_id' => (string) $patientId,
    'status' => 'SUCCESS',
]);

layout_app_header('My prescriptions', $user, 'payments');
?>
<section class="ms-card">
    <h1 class="ms-h1">My prescriptions</h1>
    <?php foreach (['Pending' => $pending, 'Dispensed' => $dispensed] as $label => $rows) { ?>
        <h2 class="ms-h2"><?= e($label) ?></h2>
        <?php if ($rows === []) { ?><div class="ms-empty-state">No <?= e(mb_strtolower($label)) ?> prescriptions.</div><?php } else { ?>
            <div class="ms-clinical-grid">
            <?php foreach ($rows as $rx) { $medication = ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? ''; $status = (string) $rx['status']; ?><article class="ms-prescription-card">
                <header class="ms-clinical-card-head"><div><h3 class="ms-clinical-card-title"><?= e($medication) ?></h3><p class="ms-clinical-card-meta">Issued <?= e((string) $rx['created_at']) ?> UTC</p></div><span class="ms-status-pill ms-status-pill-<?= e($status) ?>"><?= e($status) ?></span></header>
                <dl class="ms-detail-list"><dt>Dosage</dt><dd><?= e(ms_clinical_service()->decrypt((string) $rx['dosage_encrypted'])) ?></dd><dt>Instructions</dt><dd><?= e(ms_clinical_service()->decrypt($rx['instructions_encrypted'] ?? null) ?? '—') ?></dd><dt>Prescriber</dt><dd><?= e((string) $rx['doctor_name']) ?></dd><dt>Charge</dt><dd>KES <?= e(number_format(ClinicalCatalog::priceForMedication($medication) ?? 0)) ?></dd></dl>
            </article><?php } ?>
            </div>
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
