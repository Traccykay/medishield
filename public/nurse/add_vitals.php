<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('nurse');
$patientId = (int) ($_GET['patient_id'] ?? $_POST['patient_id'] ?? 0);
$visitId = (int) ($_GET['visit_id'] ?? $_POST['visit_id'] ?? 0);
$visit = $visitId > 0 ? ms_visit_repo()->findById($visitId) : null;
if ($patientId <= 0 || !ms_patient_service()->canViewPatient($user, $patientId)
    || ($visitId > 0 && ($visit === null || (int) $visit['patient_id'] !== $patientId || (int) $visit['nurse_id'] !== (int) $user['user_id'] || (string) $visit['status'] !== 'with_nurse'))) {
    deny_access($user, 'nurse:add_vitals');
}
$patient = ms_patient_repo()->findById($patientId);
$errors = [];
$values = ['temperature_c' => '', 'systolic_mmhg' => '', 'diastolic_mmhg' => '', 'pulse_bpm' => '', 'weight_kg' => '', 'symptoms' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    foreach (array_keys($values) as $key) {
        $values[$key] = trim((string) ($_POST[$key] ?? ''));
    }
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $errors[] = 'Your session has expired. Please try again.';
    } else {
        $result = ms_clinical_service()->recordVitals($patientId, (int) $user['user_id'], $values);
        if ($result['ok']) {
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'nurse', 'action' => 'VITALS_RECORDED', 'module' => 'nurse', 'affected_record_id' => (string) $patientId, 'status' => 'SUCCESS']);
            redirect('/nurse/view_vitals.php?patient_id=' . $patientId);
        }
        $errors = $result['errors'];
    }
}

$token = Csrf::token($_SESSION);
layout_app_header('Record vitals', $user, 'patients');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Record vitals</h1>
    <p class="ms-muted"><?= e((string) $patient['full_name']) ?> (<?= e((string) $patient['patient_number']) ?>)</p>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/nurse/add_vitals.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="patient_id" value="<?= e((string) $patientId) ?>">
        <input type="hidden" name="visit_id" value="<?= e((string) $visitId) ?>">
        <?php foreach ([
            'temperature_c' => 'Temperature C',
            'systolic_mmhg' => 'Systolic mmHg',
            'diastolic_mmhg' => 'Diastolic mmHg',
            'pulse_bpm' => 'Pulse bpm',
            'weight_kg' => 'Weight kg',
        ] as $name => $label) { ?>
            <label class="ms-label" for="<?= e($name) ?>"><?= e($label) ?></label>
            <input class="ms-input" id="<?= e($name) ?>" name="<?= e($name) ?>" value="<?= e($values[$name]) ?>" required>
        <?php } ?>
        <label class="ms-label" for="symptoms">Symptoms / observations</label>
        <textarea class="ms-input" id="symptoms" name="symptoms" rows="4"><?= e($values['symptoms']) ?></textarea>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Save vitals</button>
    </form>
</section>
<?php layout_app_footer(); ?>
