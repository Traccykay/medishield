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
require_doctor_patient_access($user, $patientId, $visitId, 'doctor:request_lab');
$patient = ms_patient_repo()->findById($patientId);
$visit = ms_visit_repo()->findById($visitId);
$errors = [];
$testName = '';
$reason = '';
if ($isPost) {
    $testName = request_string($_POST['test_name'] ?? null);
    $reason = request_string($_POST['reason'] ?? null);
    $result = ms_clinical_service()->requestLab($patientId, (int) $user['user_id'], $visitId, $recordId, $testName, $reason);
    if ($result['ok']) {
        ms_audit_log([
            'user_id' => (int) $user['user_id'],
            'user_role' => 'doctor',
            'action' => 'LAB_REQUESTED',
            'module' => 'doctor',
            'affected_record_id' => (string) $result['lab_request_id'],
            'status' => 'SUCCESS',
            'anomaly_flag' => 'NORMAL',
        ]);
        $routing = ms_visit_service()->routeFromDoctor(
            $visitId,
            $patientId,
            (int) $user['user_id'],
            'lab'
        );
        if (!$routing['ok']) {
            $errors = [
                'The lab request was saved, but the visit could not be routed. '
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
            redirect('/doctor/dashboard.php', 303);
        }
    } else {
        $errors = $result['errors'];
    }
}
$token = Csrf::token($_SESSION);
layout_app_header('Request lab', $user, 'patients');
layout_patient_context($patient ?? [], $visit ?? []);
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
