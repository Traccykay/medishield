<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('patient');
$patientId = ms_patient_service()->patientIdForUser((int) $user['user_id']);
if ($patientId === null) {
    redirect('/patient/dashboard.php');
}
$patient = ms_patient_repo()->findById($patientId);
$vitals = ms_clinical_repo()->vitalsForPatient($patientId);
$records = ms_clinical_repo()->recordsForPatient($patientId);

layout_app_header('My records', $user, 'patients');
?>
<section class="ms-card">
    <h1 class="ms-h1">My records</h1>
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
                <p><strong>Doctor:</strong> <?= e((string) $record['doctor_name']) ?></p>
                <p><strong>Diagnosis:</strong> <?= e(ms_clinical_service()->decrypt((string) $record['diagnosis_encrypted'])) ?></p>
                <p><strong>Treatment:</strong> <?= e(ms_clinical_service()->decrypt($record['treatment_encrypted'] ?? null) ?? '') ?></p>
                <p class="ms-muted"><?= e((string) $record['created_at']) ?></p>
            </div>
        <?php } ?>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
