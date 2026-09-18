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
$results = ms_clinical_repo()->labResultsForPatient($patientId);
ms_audit_read_event([
    'user_id' => (int) $user['user_id'],
    'user_role' => 'patient',
    'action' => 'PATIENT_VIEW',
    'module' => 'patient_labs',
    'affected_record_id' => (string) $patientId,
    'status' => 'SUCCESS',
]);

layout_app_header('My lab results', $user, 'patients');
?>
<section class="ms-card">
    <h1 class="ms-h1">My lab results</h1>
    <p class="ms-muted">Completed results are shown exactly as entered by the laboratory.</p>
    <?php if ($results === []) { ?><div class="ms-empty-state">No lab results yet.</div><?php } else { ?>
        <div class="ms-clinical-grid">
        <?php foreach ($results as $row) { ?><article class="ms-result-card">
            <header class="ms-clinical-card-head"><div><h2 class="ms-clinical-card-title"><?= e((string) $row['test_name']) ?></h2><p class="ms-clinical-card-meta">Completed <?= e((string) $row['created_at']) ?> UTC</p></div><span class="ms-status-pill ms-status-pill-dispensed">Completed</span></header>
            <p class="ms-clinical-value"><?= e(ms_clinical_service()->decrypt((string) $row['result_encrypted'])) ?></p>
            <dl class="ms-detail-list ms-mt"><dt>Laboratory</dt><dd><?= e((string) $row['lab_name']) ?></dd><dt>Charge</dt><dd>KES <?= e(number_format(ClinicalCatalog::priceForTest((string) $row['test_name']) ?? 0)) ?></dd></dl>
        </article><?php } ?>
        </div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
