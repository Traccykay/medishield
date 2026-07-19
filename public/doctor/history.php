<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$patientId = (int) ($_GET['patient_id'] ?? 0);
if ($patientId <= 0 || !ms_patient_repo()->isAssigned($patientId, (int) $user['user_id'])) {
    deny_access($user, 'doctor:history');
}

$patient = ms_patient_repo()->findById($patientId);
$records = ms_clinical_repo()->recordsForPatient($patientId);
$labs = ms_clinical_repo()->labResultsForPatient($patientId);
$prescriptions = ms_clinical_repo()->prescriptions('dispensed', null, $patientId);

layout_app_header('Patient history', $user, 'patients');
?>
<section class="ms-card">
    <h1 class="ms-h1">Patient medical history</h1>
    <p class="ms-muted"><?= e((string) $patient['full_name']) ?></p>
</section>
<section class="ms-card"><h2 class="ms-h2">Diagnoses and treatment</h2>
<?php foreach ($records as $record) { ?><p><strong>Diagnosis:</strong> <?= e(ms_clinical_service()->decrypt((string) $record['diagnosis_encrypted'])) ?></p><?php } ?>
</section>
<section class="ms-card"><h2 class="ms-h2">Completed lab results</h2>
<?php foreach ($labs as $lab) { ?><p><strong><?= e((string) $lab['test_name']) ?>:</strong> <?= e(ms_clinical_service()->decrypt((string) $lab['result_encrypted'])) ?></p><?php } ?>
</section>
<section class="ms-card"><h2 class="ms-h2">Dispensed medication</h2>
<?php foreach ($prescriptions as $rx) { ?><p><?= e(ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? '') ?></p><?php } ?>
</section>
<?php layout_app_footer(); ?>
