<?php

declare(strict_types=1);

/**
 * register_patient.php
 * --------------------
 * Patient registration form for administrators and receptionists. Receptionists
 * create demographics only, then select payment and place the arrival in triage.
 */

use MediShield\Security\Csrf;

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

$user = require_login();
if (!in_array((string) $user['role'], ['admin', 'receptionist'], true)) {
    deny_access($user, 'patient:register');
}

$errors = [];
$success = null;
$values = [
    'user_id' => '',
    'patient_number' => '',
    'full_name' => '',
    'date_of_birth' => '',
    'gender' => '',
    'phone' => '',
    'address' => '',
    'emergency_contact' => '',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    foreach (array_keys($values) as $key) {
        $values[$key] = trim((string) ($_POST[$key] ?? ''));
    }

    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        ms_audit_log([
            'user_id' => (int) $user['user_id'],
            'user_role' => (string) $user['role'],
            'action' => 'CSRF_REJECTED',
            'module' => 'patients',
            'status' => 'BLOCKED',
            'anomaly_flag' => 'SUSPICIOUS',
        ]);
        $errors[] = 'Your session has expired. Please try again.';
    } else {
        if ((string) $user['role'] !== 'admin') {
            $values['user_id'] = '';
        }

        $result = ms_patient_service()->registerPatient($values);
        if ($result['ok']) {
            $patientId = (int) $result['patient_id'];
            ms_audit_log([
                'user_id' => (int) $user['user_id'],
                'user_role' => (string) $user['role'],
                'action' => 'PATIENT_REGISTERED',
                'module' => 'patients',
                'affected_record_id' => (string) $patientId,
                'status' => 'SUCCESS',
            ]);
            $destination = (string) $user['role'] === 'receptionist'
                ? '/reception/intake.php?patient_id=' . $patientId
                : '/patient_profile.php?patient_id=' . $patientId;
            redirect($destination);
        }

        ms_audit_log([
            'user_id' => (int) $user['user_id'],
            'user_role' => (string) $user['role'],
            'action' => 'PATIENT_REGISTERED',
            'module' => 'patients',
            'status' => 'FAILED',
        ]);
        $errors = $result['errors'];
    }
}

$patientUsers = (string) $user['role'] === 'admin'
    ? ms_user_repo()->listByRoles(['patient'], false)
    : [];
$token = Csrf::token($_SESSION);

layout_app_header('Register patient', $user, 'patients');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Register patient</h1>
    <p class="ms-muted">Create a demographic patient record. Clinical details are not collected at reception.</p>

    <?php if ($success !== null) { layout_alert('success', $success); } ?>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>

    <form method="post" action="<?= e(ms_url('/register_patient.php')) ?>" autocomplete="off" novalidate>
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">

        <?php if ((string) $user['role'] === 'admin') { ?>
            <label class="ms-label" for="user_id">Linked patient login</label>
            <select class="ms-input" id="user_id" name="user_id">
                <option value="">No linked login</option>
                <?php foreach ($patientUsers as $patientUser) { ?>
                    <option value="<?= e((string) $patientUser['user_id']) ?>" <?= $values['user_id'] === (string) $patientUser['user_id'] ? 'selected' : '' ?>>
                        <?= e((string) $patientUser['full_name']) ?> (<?= e((string) $patientUser['email']) ?>)
                    </option>
                <?php } ?>
            </select>
            <p class="ms-help">Only admin can link a patient login account to demographics.</p>
        <?php } ?>

        <label class="ms-label" for="patient_number">Patient number</label>
        <input class="ms-input" type="text" id="patient_number" name="patient_number"
               value="<?= e($values['patient_number']) ?>" maxlength="50" required>

        <label class="ms-label" for="full_name">Full name</label>
        <input class="ms-input" type="text" id="full_name" name="full_name"
               value="<?= e($values['full_name']) ?>" maxlength="150" required>

        <label class="ms-label" for="date_of_birth">Date of birth</label>
        <input class="ms-input" type="date" id="date_of_birth" name="date_of_birth"
               value="<?= e($values['date_of_birth']) ?>" required>

        <label class="ms-label" for="gender">Gender</label>
        <select class="ms-input" id="gender" name="gender" required>
            <option value="">Select gender</option>
            <?php foreach (['male', 'female', 'other'] as $gender) { ?>
                <option value="<?= e($gender) ?>" <?= $values['gender'] === $gender ? 'selected' : '' ?>><?= e(ucfirst($gender)) ?></option>
            <?php } ?>
        </select>

        <label class="ms-label" for="phone">Phone</label>
        <input class="ms-input" type="tel" id="phone" name="phone"
               value="<?= e($values['phone']) ?>" maxlength="13" pattern="(?:\+254|254|0)[71][0-9]{8}" placeholder="0712345678 or +254712345678">
        <p class="ms-help">Use a Kenyan mobile number: 07/01, 254, or +254 format.</p>

        <label class="ms-label" for="address">Address</label>
        <textarea class="ms-input" id="address" name="address" rows="3" maxlength="255"><?= e($values['address']) ?></textarea>

        <label class="ms-label" for="emergency_contact">Emergency contact</label>
        <input class="ms-input" type="text" id="emergency_contact" name="emergency_contact"
               value="<?= e($values['emergency_contact']) ?>" maxlength="150">
        <p class="ms-help">Enter a contact name and valid Kenyan mobile number, for example: Jane Doe +254712345678.</p>

        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Register patient</button>
    </form>
</section>
<?php
layout_app_footer();
