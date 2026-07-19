<?php

declare(strict_types=1);

/**
 * patients.php
 * ------------
 * Shared patient workspace entry point. Admins can search all patient
 * demographics; nurses and doctors see only assigned patients; patient users are
 * sent to their own profile. Every actual profile view is rechecked by
 * PatientService so URL manipulation cannot expose another patient's data.
 */

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

$user = require_nav('patients');
$role = (string) $user['role'];

if ($role === 'patient') {
    $ownPatientId = ms_patient_service()->patientIdForUser((int) $user['user_id']);
    if ($ownPatientId !== null) {
        redirect('/patient_profile.php?patient_id=' . $ownPatientId);
    }
}

$query = trim((string) ($_GET['q'] ?? ''));
$patients = [];

if (in_array($role, ['admin', 'receptionist'], true)) {
    $patients = ms_patient_repo()->search($query);
} elseif (in_array($role, ['nurse', 'doctor'], true)) {
    $patients = ms_patient_repo()->assignedPatientsForStaff((int) $user['user_id']);
    if ($query !== '') {
        $needle = mb_strtolower($query);
        $patients = array_values(array_filter(
            $patients,
            static fn (array $p): bool =>
                str_contains(mb_strtolower((string) $p['full_name']), $needle)
                || str_contains(mb_strtolower((string) $p['patient_number']), $needle)
                || str_contains(mb_strtolower((string) ($p['phone'] ?? '')), $needle)
        ));
    }
}

layout_app_header('Patients', $user, 'patients');
?>
<section class="ms-card">
    <div class="ms-card-head">
        <div>
            <h1 class="ms-h1">Patients</h1>
            <p class="ms-muted">Search patient demographics and open permitted profiles.</p>
        </div>
        <?php if (in_array($role, ['admin', 'receptionist'], true)) { ?>
            <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/register_patient.php')) ?>">Register patient</a>
        <?php } ?>
    </div>

    <?php if ($role === 'patient' && $ownPatientId === null) { ?>
        <?php layout_alert('warning', 'No patient record is linked to your login yet. Please contact an administrator.'); ?>
    <?php } ?>

    <?php if (in_array($role, ['admin', 'receptionist'], true)) { ?>
        <form method="get" action="<?= e(ms_url('/patients.php')) ?>" class="ms-actions">
            <input class="ms-input" type="search" name="q" value="<?= e($query) ?>"
                   placeholder="Search by name, patient number, or phone">
            <button class="ms-btn" type="submit">Search</button>
            <a class="ms-btn" href="<?= e(ms_url('/patients.php')) ?>">Clear</a>
        </form>
    <?php } elseif (in_array($role, ['nurse', 'doctor'], true)) { ?>
        <p class="ms-muted">This list is limited to patients actively assigned to you.</p>
    <?php } ?>
</section>

<?php if ($patients !== []) { ?>
    <section class="ms-card">
        <div class="ms-table-wrap">
            <table class="ms-table">
                <thead>
                    <tr>
                        <th>Patient #</th>
                        <th>Name</th>
                        <th>DOB</th>
                        <th>Gender</th>
                        <th>Phone</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($patients as $patient) { ?>
                        <tr>
                            <td><?= e((string) $patient['patient_number']) ?></td>
                            <td><?= e((string) $patient['full_name']) ?></td>
                            <td><?= e((string) $patient['date_of_birth']) ?></td>
                            <td><?= e((string) $patient['gender']) ?></td>
                            <td><?= e((string) ($patient['phone'] ?? '')) ?></td>
                            <td>
                                <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/patient_profile.php?patient_id=' . (int) $patient['patient_id'])) ?>">View</a>
                                <?php if ($role === 'admin') { ?>
                                    <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/admin/assign_patient.php?patient_id=' . (int) $patient['patient_id'])) ?>">Assign</a>
                                <?php } ?>
                            </td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
        </div>
    </section>
<?php } elseif ($role !== 'patient') { ?>
    <section class="ms-card">
        <p class="ms-muted">No matching patients found.</p>
    </section>
<?php } ?>
<?php
layout_app_footer();
