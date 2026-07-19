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
$vitals = ms_clinical_service()->decryptVitals(ms_clinical_repo()->vitalsForPatient($patientId));
$records = ms_clinical_repo()->recordsForPatient($patientId);
$labs = ms_clinical_repo()->labResultsForPatient($patientId);
$prescriptions = ms_clinical_repo()->prescriptionsForPatient($patientId);
$dispensing = ms_clinical_repo()->dispensingForPatient($patientId);

layout_app_header('Patient history', $user, 'patients');
?>
<section class="ms-card">
    <h1 class="ms-h1">Patient medical history</h1>
    <p class="ms-muted"><?= e((string) $patient['full_name']) ?></p>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Vitals</h2>
    <?php if ($vitals === []) { ?><p class="ms-muted">No vitals recorded.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Temp</th><th>BP</th><th>Pulse</th><th>Weight</th><th>Symptoms</th><th>UTC</th></tr></thead><tbody>
        <?php foreach ($vitals as $row) { ?><tr><td><?= e((string) $row['temperature_c']) ?></td><td><?= e((string) $row['systolic_mmhg']) ?>/<?= e((string) $row['diastolic_mmhg']) ?></td><td><?= e((string) $row['pulse_bpm']) ?></td><td><?= e((string) $row['weight_kg']) ?></td><td><?= e((string) ($row['symptoms'] ?? '')) ?></td><td><?= e((string) $row['created_at']) ?></td></tr><?php } ?>
        </tbody></table></div>
    <?php } ?>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Diagnoses and treatment</h2>
    <?php if ($records === []) { ?><p class="ms-muted">No diagnosis records.</p><?php } else { ?>
        <?php foreach ($records as $record) { ?>
            <div class="ms-card">
                <p><strong>Diagnosis:</strong> <?= e(ms_clinical_service()->decrypt((string) $record['diagnosis_encrypted'])) ?></p>
                <p><strong>Treatment:</strong> <?= e(ms_clinical_service()->decrypt($record['treatment_encrypted'] ?? null) ?? '') ?></p>
                <p class="ms-muted">Created <?= e((string) $record['created_at']) ?></p>
            </div>
        <?php } ?>
    <?php } ?>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Completed lab results</h2>
    <?php if ($labs === []) { ?><p class="ms-muted">No completed lab results.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Test</th><th>Result</th><th>UTC</th></tr></thead><tbody>
        <?php foreach ($labs as $lab) { ?><tr><td><?= e((string) $lab['test_name']) ?></td><td><?= e(ms_clinical_service()->decrypt((string) $lab['result_encrypted'])) ?></td><td><?= e((string) $lab['created_at']) ?></td></tr><?php } ?>
        </tbody></table></div>
    <?php } ?>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Prescriptions</h2>
    <?php if ($prescriptions === []) { ?><p class="ms-muted">No prescriptions.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Medication</th><th>Dosage</th><th>Instructions</th><th>Status</th><th>Issued (UTC)</th></tr></thead><tbody>
        <?php foreach ($prescriptions as $rx) { ?><tr><td><?= e(ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? '') ?></td><td><?= e(ms_clinical_service()->decrypt((string) $rx['dosage_encrypted']) ?? '') ?></td><td><?= e(ms_clinical_service()->decrypt($rx['instructions_encrypted'] ?? null) ?? '') ?></td><td><?= e((string) $rx['status']) ?></td><td><?= e((string) $rx['created_at']) ?></td></tr><?php } ?>
        </tbody></table></div>
    <?php } ?>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Dispensing history</h2>
    <?php if ($dispensing === []) { ?><p class="ms-muted">No dispensing history.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Status</th><th>Remarks</th><th>Pharmacist</th><th>UTC</th></tr></thead><tbody>
        <?php foreach ($dispensing as $row) { ?><tr><td><?= e((string) $row['status']) ?></td><td><?= e((string) ($row['remarks'] ?? '')) ?></td><td><?= e((string) $row['pharmacist_name']) ?></td><td><?= e((string) $row['created_at']) ?></td></tr><?php } ?>
        </tbody></table></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
