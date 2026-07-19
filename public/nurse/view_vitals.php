<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('nurse');
$patientId = (int) ($_GET['patient_id'] ?? 0);
if ($patientId <= 0 || !ms_patient_service()->canViewPatient($user, $patientId)) {
    deny_access($user, 'nurse:view_vitals');
}
$patient = ms_patient_repo()->findById($patientId);
$vitals = ms_clinical_repo()->vitalsForPatient($patientId);

layout_app_header('Vitals history', $user, 'patients');
?>
<section class="ms-card">
    <div class="ms-card-head">
        <div><h1 class="ms-h1">Vitals history</h1><p class="ms-muted"><?= e((string) $patient['full_name']) ?></p></div>
        <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/nurse/add_vitals.php?patient_id=' . $patientId)) ?>">Add vitals</a>
    </div>
    <?php if ($vitals === []) { ?><p class="ms-muted">No vitals yet.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table">
            <thead><tr><th>Temp</th><th>BP</th><th>Pulse</th><th>Weight</th><th>Symptoms</th><th>Nurse</th><th>UTC</th></tr></thead>
            <tbody><?php foreach ($vitals as $row) { ?><tr>
                <td><?= e((string) $row['temperature_c']) ?></td>
                <td><?= e((string) $row['systolic_mmhg']) ?>/<?= e((string) $row['diastolic_mmhg']) ?></td>
                <td><?= e((string) $row['pulse_bpm']) ?></td>
                <td><?= e((string) $row['weight_kg']) ?></td>
                <td><?= e((string) ($row['symptoms'] ?? '')) ?></td>
                <td><?= e((string) $row['nurse_name']) ?></td>
                <td><?= e((string) $row['created_at']) ?></td>
            </tr><?php } ?></tbody>
        </table></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
