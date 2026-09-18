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
$patient = ms_patient_repo()->findById($patientId);
$visit = ms_visit_repo()->findById($visitId);
$errors = [];
$medicationNames = array_keys(ClinicalCatalog::MEDICATIONS);
$selectedMedicationIndexes = [];
$dosages = [];
$instructions = [];
if ($isPost) {
    $rawIndexes = is_array($_POST['medication_indices'] ?? null) ? $_POST['medication_indices'] : [];
    $dosages = is_array($_POST['medication_dosages'] ?? null) ? $_POST['medication_dosages'] : [];
    $instructions = is_array($_POST['medication_instructions'] ?? null)
        ? $_POST['medication_instructions']
        : [];
    $medications = [];
    foreach ($rawIndexes as $rawIndex) {
        $index = filter_var(request_string($rawIndex), FILTER_VALIDATE_INT);
        if ($index === false || !isset($medicationNames[$index])) {
            $medications[] = [];
            continue;
        }
        $selectedMedicationIndexes[$index] = true;
        $medications[] = [
            'medication' => $medicationNames[$index],
            'dosage' => request_string($dosages[$index] ?? null),
            'instructions' => request_string($instructions[$index] ?? null),
        ];
    }
    $result = ms_clinical_service()->issuePrescriptions(
        $patientId,
        (int) $user['user_id'],
        $visitId,
        $recordId,
        $medications
    );
    if ($result['ok']) {
        foreach ($result['prescription_ids'] as $prescriptionId) {
            ms_audit_log([
                'user_id' => (int) $user['user_id'],
                'user_role' => 'doctor',
                'action' => 'PRESCRIPTION_ISSUED',
                'module' => 'doctor',
                'affected_record_id' => (string) $prescriptionId,
                'status' => 'SUCCESS',
                'anomaly_flag' => 'NORMAL',
            ]);
        }
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
            redirect('/doctor/dashboard.php', 303);
        }
    } else {
        $errors = $result['errors'];
    }
}
$token = Csrf::token($_SESSION);
layout_app_header('Issue prescription', $user, 'patients');
layout_patient_context($patient ?? [], $visit ?? []);
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Issue prescription</h1>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/doctor/issue_prescription.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="patient_id" value="<?= e((string) $patientId) ?>">
        <input type="hidden" name="record_id" value="<?= e((string) $recordId) ?>">
        <input type="hidden" name="visit_id" value="<?= e((string) $visitId) ?>">
        <p class="ms-muted">Select every medication required. Each selected item must have a dosage.</p>
        <?php foreach ($medicationNames as $index => $name) { $cost = ClinicalCatalog::MEDICATIONS[$name]; ?>
            <section class="ms-card ms-medication-option">
                <label class="ms-label">
                    <input type="checkbox" name="medication_indices[]" value="<?= e((string) $index) ?>" <?= isset($selectedMedicationIndexes[$index]) ? 'checked' : '' ?>>
                    <?= e($name) ?> — KES <?= e(number_format($cost)) ?>
                </label>
                <label class="ms-label" for="dosage-<?= e((string) $index) ?>">Dosage</label>
                <textarea class="ms-input" id="dosage-<?= e((string) $index) ?>" name="medication_dosages[<?= e((string) $index) ?>]" rows="2"><?= e(request_string($dosages[$index] ?? null)) ?></textarea>
                <label class="ms-label" for="instructions-<?= e((string) $index) ?>">Instructions</label>
                <textarea class="ms-input" id="instructions-<?= e((string) $index) ?>" name="medication_instructions[<?= e((string) $index) ?>]" rows="2"><?= e(request_string($instructions[$index] ?? null)) ?></textarea>
            </section>
        <?php } ?>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Send selected medications to pharmacy</button>
    </form>
</section>
<?php layout_app_footer(); ?>
