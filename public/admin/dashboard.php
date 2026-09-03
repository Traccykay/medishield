<?php

declare(strict_types=1);

use MediShield\Audit\AuditDashboardSummary;

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
$integrity = ['state' => 'UNKNOWN', 'ok' => false, 'reason' => 'VERIFICATION_ERROR'];
try {
    $recent    = ms_audit()->recent(25);
    $integrity = ms_audit()->verifyChain(ms_audit_anchors());
    $localState = (string) ($integrity['local_state'] ?? $integrity['state'] ?? 'UNKNOWN');
    if ($localState !== 'PASS') {
        $recent = [];
    }
} catch (\Throwable $e) {
    error_log(json_encode([
        'event' => 'AUDIT_VERIFICATION_ERROR',
        'severity' => 'ERROR',
        'surface' => 'admin_dashboard',
        'error_type' => $e::class,
    ], JSON_UNESCAPED_SLASHES));
}
$integrityState = (string) ($integrity['state'] ?? 'UNKNOWN');
$integrityClass = match ($integrityState) {
    'PASS' => 'ms-stat-ok',
    'FAIL' => 'ms-stat-bad',
    default => 'ms-stat-warn',
};

$auditSummary = AuditDashboardSummary::fromRows($recent);
$failedEvents = $auditSummary['failed_events'];
$anomalies = $auditSummary['anomalies'];
$activeUsers  = 0;
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
    <div class="ms-card ms-stat <?= $failedEvents > 0 ? 'ms-stat-warn' : '' ?>">
        <div class="ms-stat-num" data-testid="admin-failed-events-count"><?= e((string) $failedEvents) ?></div>
        <div class="ms-stat-label">Failed events (recent)</div>
    </div>
    <div class="ms-card ms-stat <?= $anomalies > 0 ? 'ms-stat-warn' : '' ?>">
        <div class="ms-stat-num" data-testid="admin-anomaly-count"><?= e((string) $anomalies) ?></div>
        <div class="ms-stat-label">Anomaly flags (recent)</div>
    </div>
    <div class="ms-card ms-stat <?= e($integrityClass) ?>">
        <div class="ms-stat-num"><?= e($integrityState) ?></div>
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
