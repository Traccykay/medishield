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
$localIntegrityState = (string) ($integrity['local_state'] ?? $integrityState);
$integrityClass = match ($localIntegrityState) {
    'PASS' => 'ms-stat-ok',
    'FAIL' => 'ms-stat-bad',
    default => 'ms-stat-warn',
};
$anchorState = match (true) {
    $integrityState === 'PASS' => 'CURRENT',
    $integrityState === 'FAIL' => 'FAIL',
    ($integrity['reason'] ?? '') === 'EXTERNAL_ANCHOR_MISSING' => 'MISSING',
    ($integrity['reason'] ?? '') === 'UNANCHORED_SUFFIX' => 'STALE',
    default => 'UNKNOWN',
};
$anchorClass = $anchorState === 'CURRENT'
    ? 'ms-stat-ok'
    : ($anchorState === 'FAIL' ? 'ms-stat-bad' : 'ms-stat-warn');

$auditSummary = AuditDashboardSummary::fromRows($recent);
$failedEvents = $auditSummary['failed_events'];
$anomalies = $auditSummary['anomalies'];
$activeUsers  = 0;
foreach (ms_user_repo()->listAll() as $account) {
    if (($account['status'] ?? '') === 'active') {
        $activeUsers++;
    }
}

$emergencyPending = ms_emergency_access()->pendingReviewCount($user);
layout_app_header('Admin dashboard', $user, 'dashboard');
?>
<section class="ms-card ms-dashboard-hero">
    <p class="ms-dashboard-kicker">Security and operations</p>
    <div class="ms-dashboard-heading">
        <div><h1 class="ms-h1">Administrator dashboard</h1><p class="ms-muted">Manage access, supervise operations, and monitor security activity.</p></div>
        <div class="ms-actions">
            <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/admin/create_user.php')) ?>">Create user</a>
            <a class="ms-btn" href="<?= e(ms_url('/admin/users.php')) ?>">Manage users</a>
            <a class="ms-btn" href="<?= e(ms_url('/admin/audit.php')) ?>">Forensic auditing</a>
        </div>
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
    <div class="ms-card ms-stat <?= $failedEvents > 0 ? 'ms-stat-attention' : 'ms-stat-complete' ?>">
        <div class="ms-stat-num" data-testid="admin-failed-events-count"><?= e((string) $failedEvents) ?></div>
        <div class="ms-stat-label">Failed events (recent)</div>
    </div>
    <div class="ms-card ms-stat <?= $anomalies > 0 ? 'ms-stat-attention' : 'ms-stat-complete' ?>">
        <div class="ms-stat-num" data-testid="admin-anomaly-count"><?= e((string) $anomalies) ?></div>
        <div class="ms-stat-label">Anomaly flags (recent)</div>
    </div>
    <div class="ms-card ms-stat <?= e($integrityClass) ?>">
        <div class="ms-stat-num"><?= e($localIntegrityState) ?></div>
        <div class="ms-stat-label">Local audit chain</div>
    </div>
    <div class="ms-card ms-stat <?= e($anchorClass) ?>">
        <div class="ms-stat-num"><?= e($anchorState) ?></div>
        <div class="ms-stat-label">External rollback anchor</div>
    </div>
</section>

<?php if ($emergencyPending > 0) { ?>
<section class="ms-card ms-stat-attention">
    <div class="ms-card-head"><div><p class="ms-dashboard-kicker">Needs review</p><h2 class="ms-h2">Emergency access grants</h2></div><span class="ms-badge ms-badge-muted"><?= e((string) $emergencyPending) ?> pending</span></div>
    <p>Review temporary clinical-access grants and revoke any access that is no longer justified.</p>
    <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/admin/emergency_access.php')) ?>">Review emergency access</a>
</section>
<?php } ?>

<section class="ms-card">
    <h2 class="ms-h2">Security monitoring</h2>
    <p class="ms-muted">The full forensic audit log — recent logins, failed
        attempts, anomaly flags and account activity — is on its own page.</p>
    <p class="ms-mt"><a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/admin/audit.php')) ?>">Open Forensic Auditing</a></p>
</section>
<?php
layout_app_footer();
