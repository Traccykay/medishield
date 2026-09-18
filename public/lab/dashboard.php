<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('lab');
$pending = ms_clinical_repo()->labRequests('pending');
$completed = ms_clinical_repo()->completedByLabTechnician((int) $user['user_id']);

ms_audit_read($user, 'lab.dashboard', array_column($pending, 'patient_id'));
layout_app_header('Lab dashboard', $user, 'dashboard');
?>
<section class="ms-card ms-dashboard-hero">
    <p class="ms-dashboard-kicker">Laboratory workspace</p>
    <div class="ms-dashboard-heading">
        <div><h1 class="ms-h1">Laboratory dashboard</h1><p class="ms-muted">Prioritize pending tests and upload encrypted results.</p></div>
        <div class="ms-actions"><a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/lab/requests.php')) ?>">Open pending queue</a><a class="ms-btn" href="<?= e(ms_url('/lab/history.php')) ?>">Completed tests</a></div>
    </div>
</section>
<section class="ms-grid">
    <div class="ms-card ms-stat <?= $pending === [] ? 'ms-stat-complete' : 'ms-stat-attention' ?>"><div class="ms-stat-num" data-testid="lab-pending-count"><?= e((string) count($pending)) ?></div><div class="ms-stat-label">Pending requests</div></div>
    <div class="ms-card ms-stat ms-stat-complete"><div class="ms-stat-num" data-testid="lab-completed-count"><?= e((string) count($completed)) ?></div><div class="ms-stat-label">Completed by you</div></div>
</section>
<section class="ms-card">
    <div class="ms-card-head"><div><p class="ms-dashboard-kicker">Next actions</p><h2 class="ms-h2">Pending test requests</h2></div><a href="<?= e(ms_url('/lab/requests.php')) ?>">View all</a></div>
    <?php if ($pending === []) { ?><div class="ms-empty-state">The laboratory queue is clear.</div><?php } else { ?>
    <div class="ms-work-queue"><?php foreach (array_slice($pending, 0, 5) as $request) { ?><article class="ms-work-item"><div><p class="ms-work-item-title"><?= e((string) $request['test_name']) ?></p><p class="ms-work-item-meta"><?= e((string) $request['patient_number']) ?> · <?= e((string) $request['patient_name']) ?></p></div><a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/lab/upload_result.php?lab_request_id=' . (int) $request['lab_request_id'])) ?>">Upload result</a></article><?php } ?></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
