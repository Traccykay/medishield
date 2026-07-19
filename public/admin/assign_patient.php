<?php

declare(strict_types=1);

/**
 * admin/assign_patient.php
 * ------------------------
 * Admin-only assignment management. Assignments define nurse/doctor object-level
 * access to patient context, so changes are POST-only, CSRF-protected, and
 * audited as ASSIGNMENT_CHANGED.
 */

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$admin = require_area('admin');

$errors = [];
$success = null;
$selectedPatientId = (int) ($_GET['patient_id'] ?? $_POST['patient_id'] ?? 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $selectedPatientId = (int) ($_POST['patient_id'] ?? 0);
    $staffUserId = (int) ($_POST['staff_user_id'] ?? 0);
    $action = (string) ($_POST['assignment_action'] ?? 'assign');

    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        ms_audit_log([
            'user_id' => (int) $admin['user_id'],
            'user_role' => (string) $admin['role'],
            'action' => 'CSRF_REJECTED',
            'module' => 'patients',
            'status' => 'BLOCKED',
            'anomaly_flag' => 'SUSPICIOUS',
        ]);
        $errors[] = 'Your session has expired. Please try again.';
    } elseif ($action === 'unassign') {
        $result = ms_patient_service()->unassignPatient($selectedPatientId, $staffUserId);
        if ($result['ok']) {
            ms_audit_log([
                'user_id' => (int) $admin['user_id'],
                'user_role' => (string) $admin['role'],
                'action' => 'ASSIGNMENT_CHANGED',
                'module' => 'patients',
                'affected_record_id' => (string) $selectedPatientId,
                'status' => 'SUCCESS',
            ]);
            $success = 'Assignment removed.';
        } else {
            $errors = $result['errors'];
        }
    } else {
        $result = ms_patient_service()->assignPatient($selectedPatientId, $staffUserId, (int) $admin['user_id']);
        if ($result['ok']) {
            ms_audit_log([
                'user_id' => (int) $admin['user_id'],
                'user_role' => (string) $admin['role'],
                'action' => 'ASSIGNMENT_CHANGED',
                'module' => 'patients',
                'affected_record_id' => (string) $selectedPatientId,
                'status' => 'SUCCESS',
            ]);
            $success = 'Patient assigned.';
        } else {
            $errors = $result['errors'];
        }
    }
}

$patients = ms_patient_repo()->search('');
$selectedPatient = $selectedPatientId > 0 ? ms_patient_repo()->findById($selectedPatientId) : null;
$staff = ms_user_repo()->listByRoles(['nurse', 'doctor']);
$assignments = $selectedPatient !== null ? ms_patient_repo()->assignmentsForPatient($selectedPatientId) : [];
$token = Csrf::token($_SESSION);

layout_app_header('Assign patient', $admin, 'patients');
?>
<section class="ms-card">
    <div class="ms-card-head">
        <div>
            <h1 class="ms-h1">Assign patient</h1>
            <p class="ms-muted">Grant nurse/doctor access to a patient's clinical context.</p>
        </div>
        <a class="ms-btn" href="<?= e(ms_url('/patients.php')) ?>">Back to patients</a>
    </div>

    <?php if ($success !== null) { layout_alert('success', $success); } ?>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>

    <form method="get" action="<?= e(ms_url('/admin/assign_patient.php')) ?>" class="ms-actions">
        <select class="ms-input" name="patient_id" required>
            <option value="">Select patient</option>
            <?php foreach ($patients as $patient) { ?>
                <option value="<?= e((string) $patient['patient_id']) ?>" <?= $selectedPatientId === (int) $patient['patient_id'] ? 'selected' : '' ?>>
                    <?= e((string) $patient['patient_number']) ?> - <?= e((string) $patient['full_name']) ?>
                </option>
            <?php } ?>
        </select>
        <button class="ms-btn" type="submit">Open</button>
    </form>
</section>

<?php if ($selectedPatient !== null) { ?>
    <section class="ms-card">
        <h2 class="ms-h2"><?= e((string) $selectedPatient['full_name']) ?></h2>
        <p class="ms-muted">Patient number <?= e((string) $selectedPatient['patient_number']) ?></p>

        <form method="post" action="<?= e(ms_url('/admin/assign_patient.php')) ?>">
            <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
            <input type="hidden" name="patient_id" value="<?= e((string) $selectedPatientId) ?>">
            <input type="hidden" name="assignment_action" value="assign">

            <label class="ms-label" for="staff_user_id">Nurse or doctor</label>
            <select class="ms-input" id="staff_user_id" name="staff_user_id" required>
                <option value="">Select staff member</option>
                <?php foreach ($staff as $member) { ?>
                    <option value="<?= e((string) $member['user_id']) ?>">
                        <?= e((string) $member['full_name']) ?> - <?= e((string) $member['role']) ?> (<?= e((string) $member['email']) ?>)
                    </option>
                <?php } ?>
            </select>

            <button class="ms-btn ms-btn-primary ms-mt" type="submit">Assign</button>
        </form>
    </section>

    <section class="ms-card">
        <h2 class="ms-h2">Current assignments</h2>
        <?php if ($assignments === []) { ?>
            <p class="ms-muted">No active assignments.</p>
        <?php } else { ?>
            <div class="ms-table-wrap">
                <table class="ms-table">
                    <thead>
                        <tr>
                            <th>Staff</th>
                            <th>Role</th>
                            <th>Email</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($assignments as $assignment) { ?>
                            <tr>
                                <td><?= e((string) $assignment['full_name']) ?></td>
                                <td><?= e((string) $assignment['role']) ?></td>
                                <td><?= e((string) $assignment['email']) ?></td>
                                <td>
                                    <form method="post" action="<?= e(ms_url('/admin/assign_patient.php')) ?>" class="ms-inline-form">
                                        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
                                        <input type="hidden" name="patient_id" value="<?= e((string) $selectedPatientId) ?>">
                                        <input type="hidden" name="staff_user_id" value="<?= e((string) $assignment['staff_user_id']) ?>">
                                        <input type="hidden" name="assignment_action" value="unassign">
                                        <button class="ms-btn ms-btn-sm" type="submit">Unassign</button>
                                    </form>
                                </td>
                            </tr>
                        <?php } ?>
                    </tbody>
                </table>
            </div>
        <?php } ?>
    </section>
<?php } ?>
<?php
layout_app_footer();
