<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$patientId = (int) ($_GET['patient_id'] ?? $_POST['patient_id'] ?? 0);
$recordId = (int) ($_GET['record_id'] ?? $_POST['record_id'] ?? 0);
if ($patientId <= 0 || !ms_patient_service()->canViewPatient($user, $patientId)) {
    deny_access($user, 'doctor:issue_prescription');
}
$errors = [];
$medication = $dosage = $instructions = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $medication = (string) ($_POST['medication'] ?? '');
    $dosage = (string) ($_POST['dosage'] ?? '');
    $instructions = (string) ($_POST['instructions'] ?? '');
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $errors[] = 'Your session has expired. Please try again.';
    } else {
        $result = ms_clinical_service()->issuePrescription($patientId, (int) $user['user_id'], $recordId, $medication, $dosage, $instructions);
        if ($result['ok']) {
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'doctor', 'action' => 'PRESCRIPTION_ISSUED', 'module' => 'doctor', 'affected_record_id' => (string) $result['prescription_id'], 'status' => 'SUCCESS']);
            redirect('/doctor/view_patient.php?patient_id=' . $patientId);
        }
        $errors = $result['errors'];
    }
}
$token = Csrf::token($_SESSION);
layout_app_header('Issue prescription', $user, 'patients');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Issue prescription</h1>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/doctor/issue_prescription.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="patient_id" value="<?= e((string) $patientId) ?>">
        <input type="hidden" name="record_id" value="<?= e((string) $recordId) ?>">
        <label class="ms-label" for="medication">Medication</label>
        <textarea class="ms-input" id="medication" name="medication" rows="3" required><?= e($medication) ?></textarea>
        <label class="ms-label" for="dosage">Dosage</label>
        <textarea class="ms-input" id="dosage" name="dosage" rows="3" required><?= e($dosage) ?></textarea>
        <label class="ms-label" for="instructions">Instructions</label>
        <textarea class="ms-input" id="instructions" name="instructions" rows="4"><?= e($instructions) ?></textarea>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Send to pharmacy queue</button>
    </form>
</section>
<?php layout_app_footer(); ?>
