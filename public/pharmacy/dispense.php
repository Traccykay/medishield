<?php

declare(strict_types=1);

use MediShield\Security\Csrf;
use MediShield\Clinical\ClinicalCatalog;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('pharmacy');
$isPost = request_post_guard('pharmacy');
$rxId = request_positive_int(
    $isPost ? ($_POST['prescription_id'] ?? null) : ($_GET['prescription_id'] ?? null)
);
$rx = $rxId > 0 ? ms_clinical_repo()->findPrescription($rxId) : null;
$visit = $rx === null || !isset($rx['visit_id']) ? null : ms_visit_repo()->findById((int) $rx['visit_id']);
if ($rx === null || (string) $rx['status'] !== 'pending' || $visit === null || (string) $visit['status'] !== 'pharmacy') {
    redirect('/pharmacy/prescriptions.php', 303);
}
$errors = [];
$remarks = '';
$status = 'dispensed';
if ($isPost) {
    $status = request_string($_POST['status'] ?? 'dispensed');
    $remarks = request_string($_POST['remarks'] ?? null);
    $result = ms_clinical_service()->dispense($rxId, (int) $user['user_id'], $status, $remarks);
    if ($result['ok']) {
        ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'pharmacist', 'action' => $status === 'refused' ? 'MEDICATION_REFUSED' : 'MEDICATION_DISPENSED', 'module' => 'pharmacy', 'affected_record_id' => (string) $rxId, 'status' => 'SUCCESS']);
        redirect('/pharmacy/prescriptions.php');
    }
    $errors = $result['errors'];
}
ms_audit_log([
    'user_id' => (int) $user['user_id'],
    'user_role' => 'pharmacist',
    'action' => 'PATIENT_VIEW',
    'module' => 'pharmacy',
    'affected_record_id' => (string) $rx['patient_id'],
    'status' => 'SUCCESS',
]);
$token = Csrf::token($_SESSION);
layout_app_header('Dispense medication', $user, 'payments');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Dispense medication</h1>
    <p class="ms-muted"><?= e((string) $rx['patient_name']) ?> (<?= e((string) $rx['patient_number']) ?>)</p>
    <p><strong>Medication:</strong> <?= e(ms_clinical_service()->decrypt((string) $rx['medication_encrypted'])) ?></p>
    <p><strong>Billable amount:</strong> KES <?= e(number_format(ClinicalCatalog::priceForMedication(ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? '') ?? 0)) ?></p>
    <p><strong>Payment method:</strong> <?= e((string) ($visit['payment_method'] ?? 'Not recorded')) ?><?php if (($visit['insurer'] ?? null) !== null) { ?> · <?= e((string) $visit['insurer']) ?><?php } ?></p>
    <p><strong>Dosage:</strong> <?= e(ms_clinical_service()->decrypt((string) $rx['dosage_encrypted'])) ?></p>
    <p><strong>Instructions:</strong> <?= e(ms_clinical_service()->decrypt($rx['instructions_encrypted'] ?? null) ?? '') ?></p>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/pharmacy/dispense.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="prescription_id" value="<?= e((string) $rxId) ?>">
        <label class="ms-label" for="status">Outcome</label>
        <select class="ms-input" id="status" name="status">
            <option value="dispensed" <?= $status === 'dispensed' ? 'selected' : '' ?>>Dispensed</option>
            <option value="refused" <?= $status === 'refused' ? 'selected' : '' ?>>Refused</option>
        </select>
        <label class="ms-label" for="remarks">Remarks</label>
        <textarea class="ms-input" id="remarks" name="remarks" rows="4"><?= e($remarks) ?></textarea>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Record outcome</button>
    </form>
</section>
<?php layout_app_footer(); ?>
