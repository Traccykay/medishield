<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('doctor');
if (!in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'HEAD'], true)) {
    header('Allow: GET, HEAD');
    http_response_code(405);
    exit('Request method not allowed.');
}
$grantId = request_positive_int($_GET['grant_id'] ?? null);
$patientId = request_positive_int($_GET['patient_id'] ?? null);
if (!ms_emergency_access()->authorizeRead($user, $grantId, $patientId, session_id())) {
    deny_access($user, 'doctor:emergency_chart', $patientId);
}
$patient = ms_patient_repo()->findById($patientId);
$vitals = ms_clinical_service()->decryptVitals(ms_clinical_repo()->vitalsForPatient($patientId));
$records = ms_clinical_repo()->recordsForPatient($patientId);
$labs = ms_clinical_repo()->labResultsForPatient($patientId);
$prescriptions = ms_clinical_repo()->prescriptionsForPatient($patientId);
$dispensing = ms_clinical_repo()->dispensingForPatient($patientId);
// Check again after retrieval; no ordinary assignment, encounter, or write privilege is changed.
if (!ms_emergency_access()->canRead($user, $grantId, $patientId, session_id())) {
    deny_access($user, 'doctor:emergency_chart', $patientId);
}
layout_app_header('Emergency chart', $user, 'patients');
layout_alert('warning', 'Temporary read-only emergency access. Every view is audited and reviewed.');
require __DIR__ . '/../../includes/partials/clinical_history.php';
layout_app_footer();
