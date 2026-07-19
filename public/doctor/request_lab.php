<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$patientId = (int) ($_GET['patient_id'] ?? $_POST['patient_id'] ?? 0);
$recordId = (int) ($_GET['record_id'] ?? $_POST['record_id'] ?? 0);
if ($patientId <= 0 || !ms_patient_service()->canViewPatient($user, $patientId)) {
    deny_access($user, 'doctor:request_lab');
}
$errors = [];
$testName = '';
$reason = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $testName = (string) ($_POST['test_name'] ?? '');
    $reason = (string) ($_POST['reason'] ?? '');
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $errors[] = 'Your session has expired. Please try again.';
    } else {
        $result = ms_clinical_service()->requestLab($patientId, (int) $user['user_id'], $recordId, $testName, $reason);
        if ($result['ok']) {
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'doctor', 'action' => 'LAB_REQUESTED', 'module' => 'doctor', 'affected_record_id' => (string) $result['lab_request_id'], 'status' => 'SUCCESS']);
            redirect('/doctor/view_patient.php?patient_id=' . $patientId);
        }
        $errors = $result['errors'];
    }
}
$token = Csrf::token($_SESSION);
layout_app_header('Request lab', $user, 'patients');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Request lab test</h1>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/doctor/request_lab.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="patient_id" value="<?= e((string) $patientId) ?>">
        <input type="hidden" name="record_id" value="<?= e((string) $recordId) ?>">
        <label class="ms-label" for="test_name">Test name</label>
        <input class="ms-input" id="test_name" name="test_name" value="<?= e($testName) ?>" required>
        <label class="ms-label" for="reason">Reason</label>
        <textarea class="ms-input" id="reason" name="reason" rows="4"><?= e($reason) ?></textarea>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Send to lab queue</button>
    </form>
</section>
<?php layout_app_footer(); ?>
