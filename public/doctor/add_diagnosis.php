<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$patientId = (int) ($_GET['patient_id'] ?? $_POST['patient_id'] ?? 0);
if ($patientId <= 0 || !ms_patient_service()->canViewPatient($user, $patientId)) {
    deny_access($user, 'doctor:add_diagnosis');
}
$patient = ms_patient_repo()->findById($patientId);
$errors = [];
$diagnosis = '';
$treatment = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $diagnosis = (string) ($_POST['diagnosis'] ?? '');
    $treatment = (string) ($_POST['treatment'] ?? '');
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $errors[] = 'Your session has expired. Please try again.';
    } else {
        $result = ms_clinical_service()->addDiagnosis($patientId, (int) $user['user_id'], $diagnosis, $treatment);
        if ($result['ok']) {
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'doctor', 'action' => 'DIAGNOSIS_ADDED', 'module' => 'doctor', 'affected_record_id' => (string) $result['record_id'], 'status' => 'SUCCESS']);
            redirect('/doctor/view_patient.php?patient_id=' . $patientId);
        }
        $errors = $result['errors'];
    }
}
$token = Csrf::token($_SESSION);
layout_app_header('Add diagnosis', $user, 'patients');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Add diagnosis</h1>
    <p class="ms-muted"><?= e((string) $patient['full_name']) ?></p>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/doctor/add_diagnosis.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="patient_id" value="<?= e((string) $patientId) ?>">
        <label class="ms-label" for="diagnosis">Diagnosis</label>
        <textarea class="ms-input" id="diagnosis" name="diagnosis" rows="5" required><?= e($diagnosis) ?></textarea>
        <label class="ms-label" for="treatment">Treatment</label>
        <textarea class="ms-input" id="treatment" name="treatment" rows="5"><?= e($treatment) ?></textarea>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Save diagnosis</button>
    </form>
</section>
<?php layout_app_footer(); ?>
