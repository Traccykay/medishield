<?php

declare(strict_types=1);

/**
 * admin/dashboard.php
 * -------------------
 * The administrator's home page and lightweight security-monitoring view
 * (spec §6.6). It is gated to the admin area: require_area('admin') enforces
 * authentication, session timeout, the forced-password-change redirect, AND that
 * the user's role may enter the admin area (auditing + 403 on failure).
 *
 * Shown here for Deliverable 1:
 *   - Quick links to create and manage users.
 *   - The integrity status of the forensic audit chain (verifyChain()).
 *   - At-a-glance counts of recent failed events and anomaly flags.
 *
 * The detailed recent-activity TABLE now lives on its own page
 * (admin/audit.php — "Forensic Auditing"), reachable from the sidebar and the link
 * below. This page only READS the audit log; it can never edit or delete it,
 * matching the rule that even admins cannot tamper with the log.
 */

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('admin');

// Pull a small recent slice for the monitoring counters and check chain integrity.
// Both are read-only and must never take the page down, so we degrade gracefully.
$recent    = [];
$integrity = ['ok' => true, 'first_bad_log_id' => null];
try {
    $recent    = ms_audit()->recent(25);
    $integrity = ms_audit()->verifyChain();
} catch (\Throwable $e) {
    error_log('[admin/dashboard] audit read failed: ' . $e->getMessage());
}

$failedLogins = 0;
$anomalies    = 0;
$activeUsers  = 0;
foreach ($recent as $row) {
    if (($row['status'] ?? '') === 'FAILED') {
        $failedLogins++;
    }
    if (($row['anomaly_flag'] ?? 'NORMAL') !== 'NORMAL') {
        $anomalies++;
    }
}
foreach (ms_user_repo()->listAll() as $account) {
    if (($account['status'] ?? '') === 'active') {
        $activeUsers++;
    }
}

layout_app_header('Admin dashboard', $user, 'dashboard');
?>
<section class="ms-card">
    <h1 class="ms-h1">Administrator dashboard</h1>
    <p class="ms-muted">Manage users and monitor security activity.</p>

    <div class="ms-actions">
        <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/admin/create_user.php')) ?>">Create user</a>
        <a class="ms-btn" href="<?= e(ms_url('/admin/users.php')) ?>">Manage users</a>
        <a class="ms-btn" href="<?= e(ms_url('/admin/audit.php')) ?>">Forensic auditing</a>
    </div>
</section>

<section class="ms-grid">
    <div class="ms-card ms-stat">
        <div class="ms-stat-num" data-testid="admin-recent-audit-count"><?= e((string) count($recent)) ?></div>
        <div class="ms-stat-label">Recent audit events</div>
    </div>
    <div class="ms-card ms-stat">
        <div class="ms-stat-num" data-testid="admin-active-users-count"><?= e((string) $activeUsers) ?></div>
        <div class="ms-stat-label">Active accounts</div>
    </div>
    <div class="ms-card ms-stat <?= $failedLogins > 0 ? 'ms-stat-warn' : '' ?>">
        <div class="ms-stat-num"><?= e((string) $failedLogins) ?></div>
        <div class="ms-stat-label">Failed events (recent)</div>
    </div>
    <div class="ms-card ms-stat <?= $anomalies > 0 ? 'ms-stat-warn' : '' ?>">
        <div class="ms-stat-num"><?= e((string) $anomalies) ?></div>
        <div class="ms-stat-label">Anomaly flags (recent)</div>
    </div>
    <div class="ms-card ms-stat <?= $integrity['ok'] ? 'ms-stat-ok' : 'ms-stat-bad' ?>">
        <div class="ms-stat-num"><?= $integrity['ok'] ? 'OK' : 'TAMPERED' ?></div>
        <div class="ms-stat-label">Audit chain integrity</div>
    </div>
</section>

<section class="ms-card">
    <h2 class="ms-h2">Security monitoring</h2>
    <p class="ms-muted">The full forensic audit log — recent logins, failed
        attempts, anomaly flags and account activity — is on its own page.</p>
    <p class="ms-mt"><a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/admin/audit.php')) ?>">Open Forensic Auditing</a></p>
</section>
<?php
layout_app_footer();
