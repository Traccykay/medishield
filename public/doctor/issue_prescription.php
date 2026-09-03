<?php

declare(strict_types=1);

use MediShield\Security\Csrf;
use MediShield\Clinical\ClinicalCatalog;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$isPost = request_post_guard('doctor');
$patientId = request_positive_int(
    $isPost ? ($_POST['patient_id'] ?? null) : ($_GET['patient_id'] ?? null)
);
$recordId = request_positive_int(
    $isPost ? ($_POST['record_id'] ?? null) : ($_GET['record_id'] ?? null)
);
$visitId = request_positive_int(
    $isPost ? ($_POST['visit_id'] ?? null) : ($_GET['visit_id'] ?? null)
);
require_doctor_patient_access($user, $patientId, $visitId, 'doctor:issue_prescription');
$errors = [];
$medication = $dosage = $instructions = '';
if ($isPost) {
    $medication = request_string($_POST['medication'] ?? null);
    $dosage = request_string($_POST['dosage'] ?? null);
    $instructions = request_string($_POST['instructions'] ?? null);
    $result = ms_clinical_service()->issuePrescription($patientId, (int) $user['user_id'], $visitId, $recordId, $medication, $dosage, $instructions);
    if ($result['ok']) {
        ms_audit_log([
            'user_id' => (int) $user['user_id'],
            'user_role' => 'doctor',
            'action' => 'PRESCRIPTION_ISSUED',
            'module' => 'doctor',
            'affected_record_id' => (string) $result['prescription_id'],
            'status' => 'SUCCESS',
            'anomaly_flag' => 'NORMAL',
        ]);
        $routing = ms_visit_service()->routeFromDoctor(
            $visitId,
            $patientId,
            (int) $user['user_id'],
            'pharmacy'
        );
        if (!$routing['ok']) {
            $errors = [
                'The prescription was saved, but the visit could not be routed. '
                . 'Please refresh the patient record before continuing.',
            ];
            ms_audit_log([
                'user_id' => (int) $user['user_id'],
                'user_role' => 'doctor',
                'action' => 'WORKFLOW_ROUTING_FAILED',
                'module' => 'doctor',
                'affected_record_id' => (string) $patientId,
                'status' => 'FAILED',
                'anomaly_flag' => 'SUSPICIOUS',
            ]);
        } else {
            redirect('/doctor/dashboard.php');
        }
    } else {
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
        <input type="hidden" name="visit_id" value="<?= e((string) $visitId) ?>">
        <label class="ms-label" for="medication">Medication and cost</label>
        <select class="ms-input" id="medication" name="medication" required>
            <option value="">Select medication</option>
            <?php foreach (ClinicalCatalog::MEDICATIONS as $name => $cost) { ?><option value="<?= e($name) ?>" <?= $medication === $name ? 'selected' : '' ?>><?= e($name) ?> — KES <?= e(number_format($cost)) ?></option><?php } ?>
        </select>
        <label class="ms-label" for="dosage">Dosage</label>
        <textarea class="ms-input" id="dosage" name="dosage" rows="3" required><?= e($dosage) ?></textarea>
        <label class="ms-label" for="instructions">Instructions</label>
        <textarea class="ms-input" id="instructions" name="instructions" rows="4"><?= e($instructions) ?></textarea>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Send to pharmacy queue</button>
    </form>
</section>
<?php layout_app_footer(); ?>
