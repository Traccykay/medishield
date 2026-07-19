<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$patientId = (int) ($_GET['patient_id'] ?? 0);
$visitId = (int) ($_GET['visit_id'] ?? 0);
$visit = $visitId > 0 ? ms_visit_repo()->findById($visitId) : null;
if ($patientId <= 0 || $visit === null || (int) $visit['patient_id'] !== $patientId || (int) $visit['doctor_id'] !== (int) $user['user_id'] || (string) $visit['status'] !== 'with_doctor') {
    deny_access($user, 'doctor:view_patient');
}
$patient = ms_patient_repo()->findById($patientId);
$vitals = ms_clinical_repo()->vitalsForPatient($patientId);
$records = ms_clinical_repo()->recordsForPatient($patientId);
$labs = ms_clinical_repo()->labResultsForPatient($patientId);

layout_app_header('Doctor patient view', $user, 'patients');
?>
<section class="ms-card">
    <div class="ms-card-head">
        <div><h1 class="ms-h1"><?= e((string) $patient['full_name']) ?></h1><p class="ms-muted"><?= e((string) $patient['patient_number']) ?></p></div>
        <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/doctor/add_diagnosis.php?patient_id=' . $patientId . '&visit_id=' . $visitId)) ?>">Add diagnosis</a>
    </div>
    <div class="ms-actions">
        <a class="ms-btn" href="<?= e(ms_url('/patient_profile.php?patient_id=' . $patientId)) ?>">Profile</a>
    </div>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Vitals</h2>
    <?php if ($vitals === []) { ?><p class="ms-muted">No vitals recorded.</p><?php } else { ?>
    <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Temp</th><th>BP</th><th>Pulse</th><th>Weight</th><th>Symptoms</th><th>UTC</th></tr></thead><tbody>
    <?php foreach ($vitals as $row) { ?><tr><td><?= e((string) $row['temperature_c']) ?></td><td><?= e((string) $row['systolic_mmhg']) ?>/<?= e((string) $row['diastolic_mmhg']) ?></td><td><?= e((string) $row['pulse_bpm']) ?></td><td><?= e((string) $row['weight_kg']) ?></td><td><?= e((string) ($row['symptoms'] ?? '')) ?></td><td><?= e((string) $row['created_at']) ?></td></tr><?php } ?>
    </tbody></table></div><?php } ?>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Diagnoses</h2>
    <?php if ($records === []) { ?><p class="ms-muted">No diagnosis records yet.</p><?php } else { ?>
        <?php foreach ($records as $record) { ?>
            <div class="ms-card">
                <p><strong>Diagnosis:</strong> <?= e(ms_clinical_service()->decrypt((string) $record['diagnosis_encrypted'])) ?></p>
                <p><strong>Treatment:</strong> <?= e(ms_clinical_service()->decrypt($record['treatment_encrypted'] ?? null) ?? '') ?></p>
                <p class="ms-muted">Created <?= e((string) $record['created_at']) ?></p>
                <?php if ((int) $record['doctor_id'] === (int) $user['user_id']) { ?>
                    <div class="ms-actions">
                        <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/doctor/request_lab.php?patient_id=' . $patientId . '&record_id=' . (int) $record['record_id'] . '&visit_id=' . $visitId)) ?>">Request lab</a>
                        <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/doctor/issue_prescription.php?patient_id=' . $patientId . '&record_id=' . (int) $record['record_id'] . '&visit_id=' . $visitId)) ?>">Issue prescription</a>
                    </div>
                <?php } ?>
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
<?php layout_app_footer(); ?>
