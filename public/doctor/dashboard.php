<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$patients = ms_visit_service()->doctorVisits((int) $user['user_id']);
$pendingLabs = ms_clinical_repo()->labRequests('pending', (int) $user['user_id']);
$pendingRx = ms_clinical_repo()->prescriptions('pending', (int) $user['user_id']);

layout_app_header('Doctor dashboard', $user, 'dashboard');
?>
<section class="ms-card">
    <h1 class="ms-h1">Doctor dashboard</h1>
    <p class="ms-muted">Review patients assigned for the current consultation, diagnose, request labs, and prescribe.</p>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Current consultations</h2>
    <?php if ($patients === []) { ?><p class="ms-muted">No assigned patients yet.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table">
            <thead><tr><th>Patient #</th><th>Name</th><th>DOB</th><th>Actions</th></tr></thead>
            <tbody><?php foreach ($patients as $patient) { ?><tr>
                <td><?= e((string) $patient['patient_number']) ?></td>
                <td><?= e((string) $patient['full_name']) ?></td>
                <td><?= e((string) $patient['date_of_birth']) ?></td>
                <td><a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/doctor/view_patient.php?patient_id=' . (int) $patient['patient_id'] . '&visit_id=' . (int) $patient['visit_id'])) ?>">Open</a></td>
            </tr><?php } ?></tbody>
        </table></div>
    <?php } ?>
</section>
<section class="ms-grid">
    <div class="ms-card ms-stat"><div class="ms-stat-num" data-testid="doctor-consultations-count"><?= e((string) count($patients)) ?></div><div class="ms-stat-label">Current consultations</div></div>
    <div class="ms-card ms-stat"><div class="ms-stat-num" data-testid="doctor-pending-labs-count"><?= e((string) count($pendingLabs)) ?></div><div class="ms-stat-label">Pending lab requests</div></div>
    <div class="ms-card ms-stat"><div class="ms-stat-num" data-testid="doctor-pending-prescriptions-count"><?= e((string) count($pendingRx)) ?></div><div class="ms-stat-label">Pending prescriptions</div></div>
</section>
<?php layout_app_footer(); ?>
