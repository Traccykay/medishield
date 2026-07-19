<?php

declare(strict_types=1);

/**
 * patient_profile.php
 * -------------------
 * Patient demographic profile with object-level authorization. Clinical record
 * modules will add their own sections later, but they will reuse the same
 * ownership/assignment check performed here.
 */

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

$user = require_nav('patients');
$patientId = (int) ($_GET['patient_id'] ?? 0);

if ($patientId <= 0 || !ms_patient_service()->canViewPatient($user, $patientId)) {
    ms_audit_log([
        'user_id' => (int) $user['user_id'],
        'user_role' => (string) $user['role'],
        'action' => 'UNAUTHORIZED_ACCESS',
        'module' => 'patients',
        'affected_record_id' => $patientId > 0 ? (string) $patientId : null,
        'status' => 'BLOCKED',
        'anomaly_flag' => 'HIGH_RISK',
    ]);
    redirect('/unauthorized.php');
}

$patient = ms_patient_repo()->findById($patientId);
if ($patient === null) {
    redirect('/patients.php');
}

ms_audit_log([
    'user_id' => (int) $user['user_id'],
    'user_role' => (string) $user['role'],
    'action' => 'PATIENT_VIEW',
    'module' => 'patients',
    'affected_record_id' => (string) $patientId,
    'status' => 'SUCCESS',
]);

$assignments = ms_patient_repo()->assignmentsForPatient($patientId);

layout_app_header('Patient profile', $user, 'patients');
?>
<section class="ms-card">
    <div class="ms-card-head">
        <div>
            <h1 class="ms-h1"><?= e((string) $patient['full_name']) ?></h1>
            <p class="ms-muted">Patient number <?= e((string) $patient['patient_number']) ?></p>
        </div>
        <a class="ms-btn" href="<?= e(ms_url('/patients.php')) ?>">Back to patients</a>
    </div>

    <div class="ms-grid">
        <div>
            <div class="ms-stat-label">Date of birth</div>
            <div><?= e((string) $patient['date_of_birth']) ?></div>
        </div>
        <div>
            <div class="ms-stat-label">Gender</div>
            <div><?= e((string) $patient['gender']) ?></div>
        </div>
        <div>
            <div class="ms-stat-label">Phone</div>
            <div><?= e((string) ($patient['phone'] ?? '')) ?></div>
        </div>
        <div>
            <div class="ms-stat-label">Created (UTC)</div>
            <div><?= e((string) $patient['created_at']) ?></div>
        </div>
    </div>

    <h2 class="ms-h2">Contact</h2>
    <p><strong>Address:</strong> <?= e((string) ($patient['address'] ?? '')) ?></p>
    <p><strong>Emergency contact:</strong> <?= e((string) ($patient['emergency_contact'] ?? '')) ?></p>

    <?php if ((string) $user['role'] === 'admin') { ?>
        <p class="ms-mt">
            <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/admin/assign_patient.php?patient_id=' . $patientId)) ?>">Manage assignments</a>
        </p>
    <?php } ?>
</section>

<?php if (in_array((string) $user['role'], ['admin', 'nurse', 'doctor'], true)) { ?>
    <section class="ms-card">
        <h2 class="ms-h2">Active assignments</h2>
        <?php if ($assignments === []) { ?>
            <p class="ms-muted">No active nurse or doctor assignments.</p>
        <?php } else { ?>
            <div class="ms-table-wrap">
                <table class="ms-table">
                    <thead>
                        <tr>
                            <th>Staff</th>
                            <th>Role</th>
                            <th>Email</th>
                            <th>Assigned (UTC)</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($assignments as $assignment) { ?>
                            <tr>
                                <td><?= e((string) $assignment['full_name']) ?></td>
                                <td><?= e((string) $assignment['role']) ?></td>
                                <td><?= e((string) $assignment['email']) ?></td>
                                <td><?= e((string) $assignment['created_at']) ?></td>
                            </tr>
                        <?php } ?>
                    </tbody>
                </table>
            </div>
        <?php } ?>
    </section>
<?php } ?>

<section class="ms-card">
    <h2 class="ms-h2">Clinical records</h2>
    <p class="ms-muted">Vitals, diagnoses, lab results, prescriptions, and dispensing history will appear here as the clinical modules are built.</p>
</section>
<?php
layout_app_footer();
