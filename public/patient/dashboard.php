<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('patient');
$patientId = ms_patient_service()->patientIdForUser((int) $user['user_id']);
$vitals = [];
$records = [];
$labResults = [];
$prescriptions = [];
if ($patientId !== null) {
    $vitals = ms_clinical_repo()->vitalsForPatient($patientId);
    $records = ms_clinical_repo()->recordsForPatient($patientId);
    $labResults = ms_clinical_repo()->labResultsForPatient($patientId);
    $prescriptions = array_merge(
        ms_clinical_repo()->prescriptions('pending', null, $patientId),
        ms_clinical_repo()->prescriptions('dispensed', null, $patientId)
    );
}

layout_app_header('Patient dashboard', $user, 'dashboard');
?>
<section class="ms-card">
    <h1 class="ms-h1">Patient dashboard</h1>
    <?php if ($patientId === null) { ?>
        <?php layout_alert('warning', 'No patient record is linked to your login yet. Please contact the administrator.'); ?>
    <?php } else { ?>
        <p class="ms-muted">View your profile and clinical records.</p>
        <div class="ms-actions">
            <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/patient/profile.php')) ?>">Profile</a>
            <a class="ms-btn" href="<?= e(ms_url('/patient/records.php')) ?>">Records</a>
            <a class="ms-btn" href="<?= e(ms_url('/patient/lab_results.php')) ?>">Lab results</a>
            <a class="ms-btn" href="<?= e(ms_url('/patient/prescriptions.php')) ?>">Prescriptions</a>
        </div>
        <section class="ms-grid ms-mt">
            <div class="ms-card ms-stat"><div class="ms-stat-num" data-testid="patient-vitals-count"><?= e((string) count($vitals)) ?></div><div class="ms-stat-label">Vitals recorded</div></div>
            <div class="ms-card ms-stat"><div class="ms-stat-num" data-testid="patient-records-count"><?= e((string) count($records)) ?></div><div class="ms-stat-label">Diagnosis records</div></div>
            <div class="ms-card ms-stat"><div class="ms-stat-num" data-testid="patient-lab-results-count"><?= e((string) count($labResults)) ?></div><div class="ms-stat-label">Lab results available</div></div>
            <div class="ms-card ms-stat"><div class="ms-stat-num" data-testid="patient-prescriptions-count"><?= e((string) count($prescriptions)) ?></div><div class="ms-stat-label">Prescriptions</div></div>
        </section>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
