<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('nurse');
$patients = ms_visit_service()->nurseVisits((int) $user['user_id']);
$recentVitals = ms_clinical_service()->decryptVitals(
    ms_clinical_repo()->recentVitalsByNurse((int) $user['user_id'])
);

ms_audit_read($user, 'nurse.dashboard', array_column(array_merge($patients, $recentVitals), 'patient_id'));

layout_app_header('Nurse dashboard', $user, 'dashboard');
?>
<section class="ms-card ms-dashboard-hero">
    <p class="ms-dashboard-kicker">Triage workspace</p>
    <div class="ms-dashboard-heading">
        <div><h1 class="ms-h1">Nurse dashboard</h1><p class="ms-muted">Record vitals and route triaged patients to an available doctor.</p></div>
        <div class="ms-actions"><a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/nurse/triage.php')) ?>">Open triage queue</a></div>
    </div>
</section>
<section class="ms-grid">
    <div class="ms-card ms-stat <?= $patients === [] ? 'ms-stat-complete' : 'ms-stat-attention' ?>">
        <div class="ms-stat-num" data-testid="nurse-triage-count"><?= e((string) count($patients)) ?></div>
        <div class="ms-stat-label">Patients in triage</div>
    </div>
    <div class="ms-card ms-stat">
        <div class="ms-stat-num" data-testid="nurse-vitals-count"><?= e((string) count($recentVitals)) ?></div>
        <div class="ms-stat-label">Recent vitals shown</div>
    </div>
</section>

<section class="ms-card">
    <h2 class="ms-h2">Patients in triage</h2>
    <?php if ($patients === []) { ?>
        <div class="ms-empty-state">No assigned patients yet.</div>
    <?php } else { ?>
        <div class="ms-table-wrap">
            <table class="ms-table">
                <thead><tr><th>Patient #</th><th>Name</th><th>DOB</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($patients as $patient) { ?>
                    <tr>
                        <td><?= e((string) $patient['patient_number']) ?></td>
                        <td><?= e((string) $patient['full_name']) ?></td>
                        <td><?= e((string) $patient['date_of_birth']) ?></td>
                        <td>
                            <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/nurse/add_vitals.php?patient_id=' . (int) $patient['patient_id'] . '&visit_id=' . (int) $patient['visit_id'])) ?>">Vitals</a>
                            <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/nurse/assign_doctor.php?patient_id=' . (int) $patient['patient_id'] . '&visit_id=' . (int) $patient['visit_id'])) ?>">Assign doctor</a>
                        </td>
                    </tr>
                <?php } ?>
                </tbody>
            </table>
        </div>
    <?php } ?>
</section>

<section class="ms-card">
    <h2 class="ms-h2">Recent vitals</h2>
    <?php if ($recentVitals === []) { ?>
        <p class="ms-muted">No vitals recorded yet.</p>
    <?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table">
            <thead><tr><th>Patient</th><th>Temp</th><th>BP</th><th>Pulse</th><th>Weight</th><th>UTC</th></tr></thead>
            <tbody><?php foreach ($recentVitals as $row) { ?>
                <tr>
                    <td><?= e((string) $row['patient_name']) ?></td>
                    <td><?= e((string) $row['temperature_c']) ?></td>
                    <td><?= e((string) $row['systolic_mmhg']) ?>/<?= e((string) $row['diastolic_mmhg']) ?></td>
                    <td><?= e((string) $row['pulse_bpm']) ?></td>
                    <td><?= e((string) $row['weight_kg']) ?></td>
                    <td><?= e((string) $row['created_at']) ?></td>
                </tr>
            <?php } ?></tbody>
        </table></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
