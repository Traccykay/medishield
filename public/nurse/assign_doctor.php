<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('nurse');
$patientId = (int) ($_GET['patient_id'] ?? $_POST['patient_id'] ?? 0);
if ($patientId <= 0 || !ms_patient_service()->canViewPatient($user, $patientId)) {
    deny_access($user, 'nurse:assign_doctor');
}
$patient = ms_patient_repo()->findById($patientId);
$errors = [];
$success = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $doctorId = (int) ($_POST['doctor_id'] ?? 0);
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $errors[] = 'Your session has expired. Please try again.';
    } else {
        $result = ms_patient_service()->assignPatient($patientId, $doctorId, (int) $user['user_id']);
        if ($result['ok']) {
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'nurse', 'action' => 'ASSIGNMENT_CHANGED', 'module' => 'nurse', 'affected_record_id' => (string) $patientId, 'status' => 'SUCCESS']);
            $success = 'Patient assigned to doctor.';
        } else {
            $errors = $result['errors'];
        }
    }
}
$doctors = ms_user_repo()->listByRoles(['doctor']);
$assignments = ms_patient_repo()->assignmentsForPatient($patientId);
$token = Csrf::token($_SESSION);
layout_app_header('Assign doctor', $user, 'patients');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Assign doctor</h1>
    <p class="ms-muted"><?= e((string) $patient['full_name']) ?></p>
    <?php if ($success !== null) { layout_alert('success', $success); } ?>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/nurse/assign_doctor.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="patient_id" value="<?= e((string) $patientId) ?>">
        <label class="ms-label" for="doctor_id">Doctor</label>
        <select class="ms-input" id="doctor_id" name="doctor_id" required>
            <option value="">Select doctor</option>
            <?php foreach ($doctors as $doctor) { ?>
                <option value="<?= e((string) $doctor['user_id']) ?>"><?= e((string) $doctor['full_name']) ?> (<?= e((string) $doctor['email']) ?>)</option>
            <?php } ?>
        </select>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Assign doctor</button>
    </form>
    <h2 class="ms-h2 ms-mt">Current assignments</h2>
    <ul class="ms-list"><?php foreach ($assignments as $assignment) { ?><li><?= e((string) $assignment['full_name']) ?> - <?= e((string) $assignment['role']) ?></li><?php } ?></ul>
</section>
<?php layout_app_footer(); ?>
