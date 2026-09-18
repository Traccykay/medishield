<?php

declare(strict_types=1);

use MediShield\Clinical\ClinicalCatalog;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('pharmacy');
$pending = ms_clinical_repo()->pharmacyPrescriptions();
$dispensed = ms_clinical_repo()->dispensedByPharmacist((int) $user['user_id']);
$pendingTotal = array_sum(array_map(
    static fn (array $rx): int => ClinicalCatalog::priceForMedication(ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? '') ?? 0,
    $pending
));

ms_audit_read($user, 'pharmacy.dashboard', array_column($pending, 'patient_id'));
layout_app_header('Pharmacy dashboard', $user, 'dashboard');
?>
<section class="ms-card ms-dashboard-hero">
    <p class="ms-dashboard-kicker">Dispensing workspace</p>
    <div class="ms-dashboard-heading">
        <div><h1 class="ms-h1">Pharmacy dashboard</h1><p class="ms-muted">Review payment-ready prescriptions and record dispensing outcomes.</p></div>
        <div class="ms-actions"><a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/pharmacy/prescriptions.php')) ?>">Open prescription queue</a><a class="ms-btn" href="<?= e(ms_url('/pharmacy/history.php')) ?>">Dispensed history</a></div>
    </div>
</section>
<section class="ms-grid">
    <div class="ms-card ms-stat <?= $pending === [] ? 'ms-stat-complete' : 'ms-stat-attention' ?>"><div class="ms-stat-num" data-testid="pharmacy-pending-count"><?= e((string) count($pending)) ?></div><div class="ms-stat-label">Pending prescriptions</div></div>
    <div class="ms-card ms-stat ms-stat-complete"><div class="ms-stat-num" data-testid="pharmacy-dispensed-count"><?= e((string) count($dispensed)) ?></div><div class="ms-stat-label">Dispensed by you</div></div>
    <div class="ms-card ms-stat ms-stat-action"><div class="ms-stat-num" data-testid="pharmacy-pending-total">KES <?= e(number_format($pendingTotal)) ?></div><div class="ms-stat-label">Pending medication total</div></div>
</section>
<section class="ms-card">
    <div class="ms-card-head"><div><p class="ms-dashboard-kicker">Next actions</p><h2 class="ms-h2">Pending prescriptions</h2></div><a href="<?= e(ms_url('/pharmacy/prescriptions.php')) ?>">View all</a></div>
    <?php if ($pending === []) { ?><div class="ms-empty-state">The prescription queue is clear.</div><?php } else { ?>
    <div class="ms-work-queue"><?php foreach (array_slice($pending, 0, 5) as $rx) { $medication = ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? ''; ?><article class="ms-work-item"><div><p class="ms-work-item-title"><?= e($medication) ?></p><p class="ms-work-item-meta"><?= e((string) $rx['patient_number']) ?> · <?= e((string) $rx['patient_name']) ?> · KES <?= e(number_format(ClinicalCatalog::priceForMedication($medication) ?? 0)) ?></p></div><a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/pharmacy/dispense.php?prescription_id=' . (int) $rx['prescription_id'])) ?>">Review</a></article><?php } ?></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
