<?php

declare(strict_types=1);

use MediShield\Security\Csrf;
use MediShield\Visit\VisitService;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('reception');
$isPost = request_post_guard('reception');
$patientId = request_positive_int(
    $isPost ? ($_POST['patient_id'] ?? null) : ($_GET['patient_id'] ?? null)
);
$errors = [];
$paymentMethod = 'cash';
$insurer = '';

if ($isPost) {
    $paymentMethod = request_string($_POST['payment_method'] ?? null);
    $insurer = request_string($_POST['insurer'] ?? null);
    if ($patientId > 0) {
        $result = ms_visit_service()->createVisit($patientId, (int) $user['user_id'], $paymentMethod, $insurer);
        if ($result['ok']) {
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'receptionist', 'action' => 'VISIT_REGISTERED', 'module' => 'reception', 'affected_record_id' => (string) $result['visit_id'], 'status' => 'SUCCESS']);
            redirect('/reception/dashboard.php', 303);
        }
        $errors = $result['errors'];
    }
}

$patient = $patientId > 0 ? ms_patient_repo()->findById($patientId) : null;
$token = Csrf::token($_SESSION);
ms_audit_read($user, 'reception.intake', $patient === null ? [] : [(int) $patient['patient_id']]);
layout_app_header('Patient arrival', $user, 'reception');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Patient arrival</h1>
    <?php if ($patient === null) { ?>
        <p class="ms-muted">Patient not found. Search first or create the demographic record through the administrator.</p>
    <?php } else { ?>
        <p class="ms-muted"><?= e((string) $patient['full_name']) ?> · <?= e((string) $patient['patient_number']) ?></p>
        <?php foreach ($errors as $error) { layout_alert('danger', $error); } ?>
        <form method="post">
            <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
            <input type="hidden" name="patient_id" value="<?= e((string) $patientId) ?>">
            <label class="ms-label" for="payment_method">Payment method</label>
            <select class="ms-input" id="payment_method" name="payment_method" required>
                <option value="cash" <?= $paymentMethod === 'cash' ? 'selected' : '' ?>>Cash</option>
                <option value="insurance" <?= $paymentMethod === 'insurance' ? 'selected' : '' ?>>Insurance</option>
            </select>
            <label class="ms-label" for="insurer">Insurance provider (if applicable)</label>
            <select class="ms-input" id="insurer" name="insurer">
                <option value="">Select provider</option>
                <?php foreach (VisitService::INSURERS as $provider) { ?><option value="<?= e($provider) ?>" <?= $insurer === $provider ? 'selected' : '' ?>><?= e($provider) ?></option><?php } ?>
            </select>
            <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Add to triage queue</button>
        </form>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
