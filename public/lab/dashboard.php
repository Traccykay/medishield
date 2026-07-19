<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('lab');
$pending = ms_clinical_repo()->labRequests('pending');
$completed = ms_clinical_repo()->labRequests('completed');

layout_app_header('Lab dashboard', $user, 'dashboard');
?>
<section class="ms-card">
    <h1 class="ms-h1">Laboratory dashboard</h1>
    <p class="ms-muted">Process pending test requests and upload encrypted results.</p>
    <div class="ms-actions"><a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/lab/requests.php')) ?>">Open pending queue</a></div>
</section>
<section class="ms-grid">
    <div class="ms-card ms-stat"><div class="ms-stat-num"><?= e((string) count($pending)) ?></div><div class="ms-stat-label">Pending requests</div></div>
    <div class="ms-card ms-stat"><div class="ms-stat-num"><?= e((string) count($completed)) ?></div><div class="ms-stat-label">Completed requests</div></div>
</section>
<?php layout_app_footer(); ?>
