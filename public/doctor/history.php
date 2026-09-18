<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
$patientId = request_positive_int($_GET['patient_id'] ?? null);
$visitId = request_positive_int($_GET['visit_id'] ?? null);
require_doctor_patient_access($user, $patientId, $visitId, 'doctor:history');
ms_audit_read_event([
    'user_id' => (int) $user['user_id'],
    'user_role' => 'doctor',
    'action' => 'PATIENT_VIEW',
    'module' => 'doctor',
    'affected_record_id' => (string) $patientId,
    'status' => 'SUCCESS',
    'anomaly_flag' => 'NORMAL',
]);

$patient = ms_patient_repo()->findById($patientId);
$vitals = ms_clinical_service()->decryptVitals(ms_clinical_repo()->vitalsForPatient($patientId));
$records = ms_clinical_repo()->recordsForPatient($patientId);
$labs = ms_clinical_repo()->labResultsForPatient($patientId);
$prescriptions = ms_clinical_repo()->prescriptionsForPatient($patientId);
$dispensing = ms_clinical_repo()->dispensingForPatient($patientId);

layout_app_header('Patient history', $user, 'patients');
require __DIR__ . '/../../includes/partials/clinical_history.php';
layout_app_footer();
