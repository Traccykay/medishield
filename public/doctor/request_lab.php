<?php

declare(strict_types=1);

use MediShield\Security\Csrf;
use MediShield\Clinical\ClinicalCatalog;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$patientId = (int) ($_GET['patient_id'] ?? $_POST['patient_id'] ?? 0);
$recordId = (int) ($_GET['record_id'] ?? $_POST['record_id'] ?? 0);
$visitId = (int) ($_GET['visit_id'] ?? $_POST['visit_id'] ?? 0);
$visit = $visitId > 0 ? ms_visit_repo()->findById($visitId) : null;
if ($patientId <= 0 || $visit === null || (int) $visit['patient_id'] !== $patientId || (int) $visit['doctor_id'] !== (int) $user['user_id'] || (string) $visit['status'] !== 'with_doctor') {
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
            ms_visit_service()->routeFromDoctor($visitId, (int) $user['user_id'], 'lab');
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'doctor', 'action' => 'LAB_REQUESTED', 'module' => 'doctor', 'affected_record_id' => (string) $result['lab_request_id'], 'status' => 'SUCCESS']);
            redirect('/doctor/dashboard.php');
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
        <input type="hidden" name="visit_id" value="<?= e((string) $visitId) ?>">
        <label class="ms-label" for="test_name">Test name and cost</label>
        <select class="ms-input" id="test_name" name="test_name" required>
            <option value="">Select test</option>
            <?php foreach (ClinicalCatalog::LAB_TESTS as $name => $cost) { ?><option value="<?= e($name) ?>" <?= $testName === $name ? 'selected' : '' ?>><?= e($name) ?> — KES <?= e(number_format($cost)) ?></option><?php } ?>
        </select>
        <label class="ms-label" for="reason">Reason</label>
        <textarea class="ms-input" id="reason" name="reason" rows="4"><?= e($reason) ?></textarea>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Send to lab queue</button>
    </form>
</section>
<?php layout_app_footer(); ?>
