<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('patient');
$patientId = ms_patient_service()->patientIdForUser((int) $user['user_id']);

layout_app_header('Patient dashboard', $user, 'dashboard');
?>
<section class="ms-card">
    <h1 class="ms-h1">Patient dashboard</h1>
    <?php if ($patientId === null) { ?>
        <?php layout_alert('warning', 'No patient record is linked to your login yet. Please contact the administrator.'); ?>
    <?php } else { ?>
        <p class="ms-muted">View your profile and clinical records.</p>
        <div class="ms-actions">
            <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/patient/profile.php')) ?>">Profile</a>
            <a class="ms-btn" href="<?= e(ms_url('/patient/records.php')) ?>">Records</a>
            <a class="ms-btn" href="<?= e(ms_url('/patient/lab_results.php')) ?>">Lab results</a>
            <a class="ms-btn" href="<?= e(ms_url('/patient/prescriptions.php')) ?>">Prescriptions</a>
        </div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
