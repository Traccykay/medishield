<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';

$user = require_area('patient');
$patientId = ms_patient_service()->patientIdForUser((int) $user['user_id']);
if ($patientId === null) {
    redirect('/patient/dashboard.php');
}
redirect('/patient_profile.php?patient_id=' . $patientId);
