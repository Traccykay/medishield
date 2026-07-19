<?php

declare(strict_types=1);

use MediShield\Security\Csrf;
use MediShield\Clinical\ClinicalCatalog;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('pharmacy');
$rxId = (int) ($_GET['prescription_id'] ?? $_POST['prescription_id'] ?? 0);
$rx = $rxId > 0 ? ms_clinical_repo()->findPrescription($rxId) : null;
if ($rx === null || (string) $rx['status'] !== 'pending') {
    redirect('/pharmacy/prescriptions.php');
}
$visit = $rx === null ? null : ms_visit_repo()->openVisitForPatient((int) $rx['patient_id']);
$errors = [];
$remarks = '';
$status = 'dispensed';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $status = (string) ($_POST['status'] ?? 'dispensed');
    $remarks = (string) ($_POST['remarks'] ?? '');
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $errors[] = 'Your session has expired. Please try again.';
    } else {
        $result = ms_clinical_service()->dispense($rxId, (int) $user['user_id'], $status, $remarks);
        if ($result['ok']) {
            if ($status === 'dispensed') {
                ms_visit_service()->completePharmacyVisit((int) $rx['patient_id']);
            }
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'pharmacist', 'action' => 'MEDICATION_DISPENSED', 'module' => 'pharmacy', 'affected_record_id' => (string) $rxId, 'status' => 'SUCCESS']);
            redirect('/pharmacy/prescriptions.php');
        }
        $errors = $result['errors'];
    }
}
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
