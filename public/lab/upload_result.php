<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('lab');
$requestId = (int) ($_GET['lab_request_id'] ?? $_POST['lab_request_id'] ?? 0);
$request = $requestId > 0 ? ms_clinical_repo()->findLabRequest($requestId) : null;
if ($request === null || (string) $request['status'] !== 'pending') {
    redirect('/lab/requests.php');
}
$errors = [];
$resultText = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $resultText = (string) ($_POST['result'] ?? '');
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $errors[] = 'Your session has expired. Please try again.';
    } else {
        $result = ms_clinical_service()->uploadLabResult($requestId, (int) $user['user_id'], $resultText);
        if ($result['ok']) {
            ms_visit_service()->returnFromLab((int) $request['patient_id']);
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'lab', 'action' => 'LAB_RESULT_UPLOADED', 'module' => 'lab', 'affected_record_id' => (string) $requestId, 'status' => 'SUCCESS']);
            redirect('/lab/requests.php');
        }
        $errors = $result['errors'];
    }
}
$token = Csrf::token($_SESSION);
layout_app_header('Upload lab result', $user, 'reports');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Upload lab result</h1>
    <p class="ms-muted"><?= e((string) $request['test_name']) ?> for <?= e((string) $request['patient_name']) ?> (<?= e((string) $request['patient_number']) ?>)</p>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/lab/upload_result.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="lab_request_id" value="<?= e((string) $requestId) ?>">
        <label class="ms-label" for="result">Result</label>
        <textarea class="ms-input" id="result" name="result" rows="8" required><?= e($resultText) ?></textarea>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Complete request</button>
    </form>
</section>
<?php layout_app_footer(); ?>
