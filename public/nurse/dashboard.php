<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('nurse');
$patients = ms_patient_repo()->assignedPatientsForStaff((int) $user['user_id']);
$recentVitals = ms_clinical_repo()->recentVitalsByNurse((int) $user['user_id']);

layout_app_header('Nurse dashboard', $user, 'dashboard');
?>
<section class="ms-card">
    <h1 class="ms-h1">Nurse dashboard</h1>
    <p class="ms-muted">Record vitals for assigned patients and route them to a doctor.</p>
</section>

<section class="ms-card">
    <h2 class="ms-h2">Assigned patients</h2>
    <?php if ($patients === []) { ?>
        <p class="ms-muted">No assigned patients yet.</p>
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
                            <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/nurse/add_vitals.php?patient_id=' . (int) $patient['patient_id'])) ?>">Vitals</a>
                            <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/nurse/assign_doctor.php?patient_id=' . (int) $patient['patient_id'])) ?>">Assign doctor</a>
                            <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/patient_profile.php?patient_id=' . (int) $patient['patient_id'])) ?>">Profile</a>
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
