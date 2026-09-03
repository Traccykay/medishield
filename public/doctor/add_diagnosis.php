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
$visitId = request_positive_int(
    $isPost ? ($_POST['visit_id'] ?? null) : ($_GET['visit_id'] ?? null)
);
require_doctor_patient_access($user, $patientId, $visitId, 'doctor:add_diagnosis');
$patient = ms_patient_repo()->findById($patientId);
$errors = [];
$diagnosis = '';
$treatment = '';
$labTests = [];
$medicationIndices = [];
$selectedMedicationIndexes = [];
$dosages = [];
$instructions = [];
$medicationNames = array_keys(ClinicalCatalog::MEDICATIONS);
if ($isPost) {
    $diagnosis = request_string($_POST['diagnosis'] ?? null);
    $treatment = request_string($_POST['treatment'] ?? null);
    $rawLabTests = is_array($_POST['lab_tests'] ?? null) ? $_POST['lab_tests'] : [];
    $labTests = array_values(array_filter(
        array_map('request_string', $rawLabTests),
        static fn (string $test): bool => $test !== ''
    ));
    $medicationIndices = is_array($_POST['medication_indices'] ?? null) ? $_POST['medication_indices'] : [];
    $dosages = is_array($_POST['medication_dosages'] ?? null) ? $_POST['medication_dosages'] : [];
    $instructions = is_array($_POST['medication_instructions'] ?? null) ? $_POST['medication_instructions'] : [];
    $medications = [];
    foreach ($medicationIndices as $index) {
        $index = filter_var(request_string($index), FILTER_VALIDATE_INT);
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
    $result = ms_clinical_service()->submitConsultation(
        $patientId,
        (int) $user['user_id'],
        $visitId,
        $diagnosis,
        $treatment,
        $labTests,
        $medications
    );
    if ($result['ok']) {
        ms_audit_log([
            'user_id' => (int) $user['user_id'],
            'user_role' => 'doctor',
            'action' => 'DIAGNOSIS_ADDED',
            'module' => 'doctor',
            'affected_record_id' => (string) $result['record_id'],
            'status' => 'SUCCESS',
            'anomaly_flag' => 'NORMAL',
        ]);
        foreach ($result['lab_request_ids'] as $labRequestId) {
            ms_audit_log([
                'user_id' => (int) $user['user_id'],
                'user_role' => 'doctor',
                'action' => 'LAB_REQUESTED',
                'module' => 'doctor',
                'affected_record_id' => (string) $labRequestId,
                'status' => 'SUCCESS',
                'anomaly_flag' => 'NORMAL',
            ]);
        }
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
        $redirectPath = '/doctor/view_patient.php?patient_id=' . $patientId . '&visit_id=' . $visitId;
        $destination = $result['lab_request_ids'] !== []
            ? 'lab'
            : ($result['prescription_ids'] !== [] ? 'pharmacy' : null);
        if ($destination !== null) {
            $routing = ms_visit_service()->routeFromDoctor(
                $visitId,
                $patientId,
                (int) $user['user_id'],
                $destination
            );
            if (!$routing['ok']) {
                $errors = [
                    'The consultation and selected orders were saved, but the visit could not be routed. '
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
                $redirectPath = '/doctor/dashboard.php';
            }
        }
        if ($errors === []) {
            redirect($redirectPath);
        }
    } else {
        $errors = $result['errors'];
    }
}
$token = Csrf::token($_SESSION);
layout_app_header('Add diagnosis', $user, 'patients');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Add diagnosis</h1>
    <p class="ms-muted"><?= e((string) $patient['full_name']) ?></p>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/doctor/add_diagnosis.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="patient_id" value="<?= e((string) $patientId) ?>">
        <input type="hidden" name="visit_id" value="<?= e((string) $visitId) ?>">
        <label class="ms-label" for="diagnosis">Diagnosis</label>
        <textarea class="ms-input" id="diagnosis" name="diagnosis" rows="5" required><?= e($diagnosis) ?></textarea>
        <label class="ms-label" for="treatment">Treatment</label>
        <textarea class="ms-input" id="treatment" name="treatment" rows="5"><?= e($treatment) ?></textarea>
        <fieldset class="ms-card">
            <legend class="ms-h2">Lab tests</legend>
            <p class="ms-muted">Select every test required for this consultation.</p>
            <?php foreach (ClinicalCatalog::LAB_TESTS as $name => $price) { ?>
                <label class="ms-label"><input type="checkbox" name="lab_tests[]" value="<?= e($name) ?>" <?= in_array($name, $labTests, true) ? 'checked' : '' ?>> <?= e($name) ?> — KES <?= e(number_format($price)) ?></label>
            <?php } ?>
        </fieldset>
        <fieldset class="ms-card">
            <legend class="ms-h2">Medications</legend>
            <p class="ms-muted">For each selected medication, provide its dosage. Catalog prices are resolved on the server.</p>
            <?php foreach ($medicationNames as $index => $name) { $price = ClinicalCatalog::MEDICATIONS[$name]; ?>
                <div class="ms-card">
                    <label class="ms-label"><input type="checkbox" name="medication_indices[]" value="<?= e((string) $index) ?>" <?= isset($selectedMedicationIndexes[$index]) ? 'checked' : '' ?>> <?= e($name) ?> — KES <?= e(number_format($price)) ?></label>
                    <label class="ms-label" for="dosage-<?= e((string) $index) ?>">Dosage for <?= e($name) ?></label>
                    <textarea class="ms-input" id="dosage-<?= e((string) $index) ?>" name="medication_dosages[<?= e((string) $index) ?>]" rows="2"><?= e((string) ($dosages[$index] ?? '')) ?></textarea>
                    <label class="ms-label" for="instructions-<?= e((string) $index) ?>">Instructions for <?= e($name) ?></label>
                    <textarea class="ms-input" id="instructions-<?= e((string) $index) ?>" name="medication_instructions[<?= e((string) $index) ?>]" rows="2"><?= e((string) ($instructions[$index] ?? '')) ?></textarea>
                </div>
            <?php } ?>
        </fieldset>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Save consultation and selected orders</button>
    </form>
</section>
<?php layout_app_footer(); ?>
