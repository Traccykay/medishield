<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$isPost = request_post_guard('doctor');
$error = '';
if ($isPost) {
    // Exact patient number only: this exception does not introduce a patient directory.
    $number = trim(request_string($_POST['patient_number'] ?? null));
    $lookup = ms_db()->prepare('SELECT patient_id FROM patients WHERE patient_number = :number');
    $lookup->execute([':number' => mb_substr($number, 0, 50)]);
    $patientId = (int) ($lookup->fetchColumn() ?: 0);
    $grantId = ms_emergency_access()->request(
        $user, $patientId, request_string($_POST['password'] ?? null),
        request_string($_POST['reason'] ?? null), session_id(), ms_client_ip()
    );
    if ($grantId !== null) {
        redirect('/doctor/emergency_chart.php?grant_id=' . $grantId . '&patient_id=' . $patientId);
    }
    $error = 'Emergency access could not be granted. Check your details or contact the administrator.';
}
layout_app_header('Emergency access', $user, 'patients');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Emergency patient access</h1>
    <p>Use only when urgent care requires access outside your assigned consultation.
        Access is read-only for 15 minutes, and every use is flagged for administrator review.</p>
    <?php if ($error !== '') { layout_alert('danger', $error); } ?>
    <form method="post" class="ms-form-stack">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e(Csrf::token($_SESSION)) ?>">
        <fieldset class="ms-form-section"><legend>Patient and justification</legend>
        <label class="ms-label" for="patient_number">Exact patient number <span class="ms-required">Required</span></label>
        <input class="ms-input" id="patient_number" name="patient_number" maxlength="50" required>
        <label class="ms-label" for="reason">Why emergency access is necessary <span class="ms-required">Required</span></label>
        <textarea class="ms-input" id="reason" name="reason" minlength="10" maxlength="1000" required></textarea>
        <p class="ms-muted">Describe the need for access. Avoid including diagnoses or other clinical details.</p>
        </fieldset><fieldset class="ms-form-section"><legend>Reauthentication</legend>
        <label class="ms-label" for="password">Confirm your password <span class="ms-required">Required</span></label>
        <input class="ms-input" id="password" name="password" type="password" autocomplete="current-password" required>
        <p class="ms-help">Access is read-only, lasts 15 minutes, and is reviewed by an administrator.</p>
        </fieldset>
        <button class="ms-btn ms-btn-primary" type="submit">Open temporary read-only access</button>
    </form>
</section>
<?php layout_app_footer(); ?>
