<?php

declare(strict_types=1);

use MediShield\Clinical\ClinicalCatalog;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('pharmacy');
$pending = ms_clinical_repo()->prescriptions('pending');
$dispensed = ms_clinical_repo()->prescriptions('dispensed');
$pendingTotal = array_sum(array_map(
    static fn (array $rx): int => ClinicalCatalog::priceForMedication(ms_clinical_service()->decrypt((string) $rx['medication_encrypted']) ?? '') ?? 0,
    $pending
));

layout_app_header('Pharmacy dashboard', $user, 'dashboard');
?>
<section class="ms-card">
    <h1 class="ms-h1">Pharmacy dashboard</h1>
    <p class="ms-muted">Process pending prescriptions, confirm billing, and record dispensing outcomes.</p>
    <div class="ms-actions"><a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/pharmacy/prescriptions.php')) ?>">Open prescription queue</a></div>
</section>
<section class="ms-grid">
    <div class="ms-card ms-stat"><div class="ms-stat-num"><?= e((string) count($pending)) ?></div><div class="ms-stat-label">Pending prescriptions</div></div>
    <div class="ms-card ms-stat"><div class="ms-stat-num"><?= e((string) count($dispensed)) ?></div><div class="ms-stat-label">Dispensed prescriptions</div></div>
    <div class="ms-card ms-stat"><div class="ms-stat-num">KES <?= e(number_format($pendingTotal)) ?></div><div class="ms-stat-label">Pending medication total</div></div>
</section>
<?php layout_app_footer(); ?>
