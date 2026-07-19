<?php

declare(strict_types=1);

use MediShield\Clinical\ClinicalCatalog;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('patient');
$patientId = ms_patient_service()->patientIdForUser((int) $user['user_id']);
if ($patientId === null) {
    redirect('/patient/dashboard.php');
}
$results = ms_clinical_repo()->labResultsForPatient($patientId);

layout_app_header('My lab results', $user, 'patients');
?>
<section class="ms-card">
    <h1 class="ms-h1">My lab results</h1>
    <?php if ($results === []) { ?><p class="ms-muted">No lab results yet.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Test</th><th>Cost</th><th>Result</th><th>Lab tech</th><th>UTC</th></tr></thead><tbody>
        <?php foreach ($results as $row) { ?><tr><td><?= e((string) $row['test_name']) ?></td><td>KES <?= e(number_format(ClinicalCatalog::priceForTest((string) $row['test_name']) ?? 0)) ?></td><td><?= e(ms_clinical_service()->decrypt((string) $row['result_encrypted'])) ?></td><td><?= e((string) $row['lab_name']) ?></td><td><?= e((string) $row['created_at']) ?></td></tr><?php } ?>
        </tbody></table></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
