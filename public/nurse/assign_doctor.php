<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('nurse');
$isPost = request_post_guard('nurse');
$patientId = request_positive_int(
    $isPost ? ($_POST['patient_id'] ?? null) : ($_GET['patient_id'] ?? null)
);
$visitId = request_positive_int(
    $isPost ? ($_POST['visit_id'] ?? null) : ($_GET['visit_id'] ?? null)
);
$visit = $visitId > 0 ? ms_visit_repo()->findById($visitId) : null;
if ($patientId <= 0 || $visit === null || (int) $visit['patient_id'] !== $patientId || (int) $visit['nurse_id'] !== (int) $user['user_id'] || (string) $visit['status'] !== 'with_nurse') {
    deny_access($user, 'nurse:assign_doctor');
}
$patient = ms_patient_repo()->findById($patientId);
$errors = [];
$success = null;
if ($isPost) {
    $doctorId = request_positive_int($_POST['doctor_id'] ?? null);
    $result = ms_visit_service()->assignDoctor($visitId, (int) $user['user_id'], $doctorId);
    if ($result['ok']) {
        ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'nurse', 'action' => 'ASSIGNMENT_CHANGED', 'module' => 'nurse', 'affected_record_id' => (string) $patientId, 'status' => 'SUCCESS']);
        redirect('/nurse/dashboard.php', 303);
    } else {
        $errors = $result['errors'];
    }
}
$doctors = ms_visit_service()->availableDoctors();
$assignments = ms_patient_repo()->assignmentsForPatient($patientId);
$token = Csrf::token($_SESSION);
ms_audit_read($user, 'nurse.assign_doctor', [$patientId]);
layout_app_header('Assign doctor', $user, 'patients');
layout_patient_context($patient ?? [], $visit ?? []);
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Assign doctor</h1>
    <p class="ms-muted"><?= e((string) $patient['full_name']) ?></p>
    <?php if ($success !== null) { layout_alert('success', $success); } ?>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>
    <form method="post" action="<?= e(ms_url('/nurse/assign_doctor.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <input type="hidden" name="patient_id" value="<?= e((string) $patientId) ?>">
        <input type="hidden" name="visit_id" value="<?= e((string) $visitId) ?>">
        <label class="ms-label" for="doctor_id">Doctor</label>
        <select class="ms-input" id="doctor_id" name="doctor_id" required>
            <option value="">Select doctor</option>
            <?php foreach ($doctors as $doctor) { ?>
                <option value="<?= e((string) $doctor['user_id']) ?>"><?= e((string) $doctor['full_name']) ?> (<?= e((string) $doctor['email']) ?>)</option>
            <?php } ?>
        </select>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Assign doctor</button>
    </form>
    <p class="ms-help">Doctors with an active consultation are excluded from this list.</p>
</section>
<?php layout_app_footer(); ?>
