<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('reception');
$query = trim((string) ($_GET['q'] ?? ''));
$patients = $query === '' ? [] : ms_patient_repo()->search($query);
$queue = ms_visit_service()->triageQueue();

layout_app_header('Reception dashboard', $user, 'reception');
?>
<section class="ms-card ms-dashboard-hero">
    <h1 class="ms-h1">Reception dashboard</h1>
    <p class="ms-muted">Search demographics, register arrivals, record payment choice, and send patients to triage.</p>
    <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/register_patient.php')) ?>">Register new patient</a>
</section>
<section class="ms-grid">
    <div class="ms-card ms-stat">
        <div class="ms-stat-num" data-testid="reception-triage-count"><?= e((string) count($queue)) ?></div>
        <div class="ms-stat-label">Waiting for triage</div>
    </div>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Find patient</h2>
    <form method="get" class="ms-actions">
        <input class="ms-input" type="search" name="q" value="<?= e($query) ?>" placeholder="Name, patient number, or phone">
        <button class="ms-btn" type="submit">Search</button>
    </form>
    <?php if ($query !== '') { ?>
        <?php if ($patients === []) { ?><p class="ms-muted">No matching patient. Register a new patient.</p><?php } else { ?>
            <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Patient #</th><th>Name</th><th>Phone</th><th>Action</th></tr></thead><tbody>
            <?php foreach ($patients as $patient) { ?><tr><td><?= e((string) $patient['patient_number']) ?></td><td><?= e((string) $patient['full_name']) ?></td><td><?= e((string) ($patient['phone'] ?? '')) ?></td><td><a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/reception/intake.php?patient_id=' . (int) $patient['patient_id'])) ?>">Start visit</a></td></tr><?php } ?>
            </tbody></table></div>
        <?php } ?>
    <?php } ?>
</section>
<section class="ms-card">
    <h2 class="ms-h2">Waiting for triage</h2>
    <?php if ($queue === []) { ?><p class="ms-muted">No patients waiting.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Patient</th><th>Payment</th><th>Insurance</th><th>Arrived (UTC)</th></tr></thead><tbody>
        <?php foreach ($queue as $visit) { ?><tr><td><?= e((string) $visit['patient_name']) ?></td><td><?= e((string) $visit['payment_method']) ?></td><td><?= e((string) ($visit['insurer'] ?? '')) ?></td><td><?= e((string) $visit['created_at']) ?></td></tr><?php } ?>
        </tbody></table></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
