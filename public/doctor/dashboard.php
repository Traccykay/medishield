<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$patients = ms_visit_service()->doctorVisits((int) $user['user_id']);
$pendingLabs = ms_clinical_repo()->countLabRequestsByDoctor((int) $user['user_id']);
$pendingRx = ms_clinical_repo()->countPrescriptionsByDoctor((int) $user['user_id']);

ms_audit_read($user, 'doctor.dashboard', array_column($patients, 'patient_id'));
layout_app_header('Doctor dashboard', $user, 'dashboard');
?>
<section class="ms-card ms-dashboard-hero">
    <p class="ms-dashboard-kicker">Clinical workspace</p>
    <div class="ms-dashboard-heading">
        <div><h1 class="ms-h1">Doctor dashboard</h1><p class="ms-muted">Review current consultations and outstanding clinical orders.</p></div>
        <div class="ms-actions"><a class="ms-btn" href="<?= e(ms_url('/doctor/emergency_access.php')) ?>">Emergency read-only access</a></div>
    </div>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Current consultations</h2>
    <?php if ($patients === []) { ?><div class="ms-empty-state">No assigned patients yet.</div><?php } else { ?>
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
    <div class="ms-card ms-stat ms-stat-action"><div class="ms-stat-num" data-testid="doctor-consultations-count"><?= e((string) count($patients)) ?></div><div class="ms-stat-label">Current consultations</div></div>
    <div class="ms-card ms-stat <?= $pendingLabs > 0 ? 'ms-stat-attention' : 'ms-stat-complete' ?>"><div class="ms-stat-num" data-testid="doctor-pending-labs-count"><?= e((string) $pendingLabs) ?></div><div class="ms-stat-label">Pending lab requests</div></div>
    <div class="ms-card ms-stat <?= $pendingRx > 0 ? 'ms-stat-attention' : 'ms-stat-complete' ?>"><div class="ms-stat-num" data-testid="doctor-pending-prescriptions-count"><?= e((string) $pendingRx) ?></div><div class="ms-stat-label">Pending prescriptions</div></div>
</section>
<?php layout_app_footer(); ?>
