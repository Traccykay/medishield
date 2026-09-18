<?php

declare(strict_types=1);

use MediShield\Clinical\ClinicalCatalog;
use MediShield\Support\ListPage;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('pharmacy');
$prescriptions = ms_clinical_repo()->pharmacyPrescriptions();
$query = trim(request_string($_GET['q'] ?? null));
if ($query !== '') {
    $needle = mb_strtolower($query);
    $prescriptions = array_values(array_filter($prescriptions, static function (array $row) use ($needle): bool {
        $medication = ms_clinical_service()->decrypt((string) $row['medication_encrypted']) ?? '';
        return str_contains(mb_strtolower($medication), $needle)
            || str_contains(mb_strtolower((string) $row['patient_number']), $needle)
            || str_contains(mb_strtolower((string) $row['patient_name']), $needle);
    }));
}
$prescriptionPage = ListPage::fromRows($prescriptions, $_GET['page'] ?? null, $_GET['per_page'] ?? null);
$prescriptions = $prescriptionPage['rows'];

ms_audit_read($user, 'pharmacy.prescriptions', array_column($prescriptions, 'patient_id'));
layout_app_header('Prescription queue', $user, 'payments');
?>
<section class="ms-card">
    <h1 class="ms-h1">Pending prescriptions</h1>
    <form method="get" class="ms-filter-bar"><label class="ms-sr-only" for="prescription-search">Search prescriptions</label><input class="ms-input" id="prescription-search" type="search" name="q" value="<?= e($query) ?>" placeholder="Medication, patient name, or patient number"><label class="ms-sr-only" for="prescription-page-size">Results per page</label><select class="ms-input" id="prescription-page-size" name="per_page"><?php foreach (ListPage::SIZES as $size) { ?><option value="<?= e((string) $size) ?>" <?= $prescriptionPage['per_page'] === $size ? 'selected' : '' ?>><?= e((string) $size) ?> per page</option><?php } ?></select><button class="ms-btn ms-btn-primary" type="submit">Apply</button><a class="ms-btn" href="<?= e(ms_url('/pharmacy/prescriptions.php')) ?>">Clear</a></form>
    <?php if ($prescriptions === []) { ?><p class="ms-muted">No pending prescriptions.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table">
            <thead><tr><th>Patient #</th><th>Name</th><th>Medication</th><th>Cost</th><th>Dosage</th><th>Doctor</th><th>Action</th></tr></thead>
            <tbody><?php foreach ($prescriptions as $rx) { ?><tr>
                <td><?= e((string) $rx['patient_number']) ?></td>
                <td><?= e((string) $rx['patient_name']) ?></td>
                <?php $medication = ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? ''; ?>
                <td><?= e($medication) ?></td>
                <td>KES <?= e(number_format(ClinicalCatalog::priceForMedication($medication) ?? 0)) ?></td>
                <td><?= e(ms_clinical_service()->decrypt((string) $rx['dosage_encrypted'])) ?></td>
                <td><?= e((string) $rx['doctor_name']) ?></td>
                <td><a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/pharmacy/dispense.php?prescription_id=' . (int) $rx['prescription_id'])) ?>">Dispense</a></td>
            </tr><?php } ?></tbody>
        </table></div>
        <?php layout_pagination($prescriptionPage, '/pharmacy/prescriptions.php', ['q' => $query]); ?>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
