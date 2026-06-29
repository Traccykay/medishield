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
 *   - The most recent audit events, with failed logins / anomalies highlighted,
 *     satisfying "view audit logs / anomaly flags / failed login attempts".
 *
 * This page only READS the audit log (recent()); it can never edit or delete it,
 * matching the rule that even admins cannot tamper with the log.
 */

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('admin');

// Pull a small recent slice for the monitoring panel and check chain integrity.
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
foreach ($recent as $row) {
    if (($row['status'] ?? '') === 'FAILED') {
        $failedLogins++;
    }
    if (($row['anomaly_flag'] ?? 'NORMAL') !== 'NORMAL') {
        $anomalies++;
    }
}

layout_header('Admin dashboard', $user);
?>
<section class="ms-card">
    <h1 class="ms-h1">Administrator dashboard</h1>
    <p class="ms-muted">Manage users and monitor security activity.</p>

    <div class="ms-actions">
        <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/admin/create_user.php')) ?>">Create user</a>
        <a class="ms-btn" href="<?= e(ms_url('/admin/users.php')) ?>">Manage users</a>
    </div>
</section>

<section class="ms-grid">
    <div class="ms-card ms-stat">
        <div class="ms-stat-num"><?= e((string) count($recent)) ?></div>
        <div class="ms-stat-label">Recent audit events</div>
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
    <h2 class="ms-h2">Recent security activity</h2>

    <?php if ($recent === []) { ?>
        <p class="ms-muted">No audit events recorded yet.</p>
    <?php } else { ?>
        <div class="ms-table-wrap">
            <table class="ms-table">
                <thead>
                    <tr>
                        <th>Time (UTC)</th>
                        <th>User</th>
                        <th>Role</th>
                        <th>Action</th>
                        <th>Module</th>
                        <th>Status</th>
                        <th>Anomaly</th>
                        <th>IP</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($recent as $row) {
                        $status  = (string) ($row['status'] ?? '');
                        $anomaly = (string) ($row['anomaly_flag'] ?? 'NORMAL');
                        $rowClass = $status === 'FAILED' || $status === 'BLOCKED'
                            ? 'ms-row-warn'
                            : ($anomaly !== 'NORMAL' ? 'ms-row-warn' : '');
                    ?>
                        <tr class="<?= e($rowClass) ?>">
                            <td><?= e((string) ($row['created_at'] ?? '')) ?></td>
                            <td><?= e((string) ($row['user_id'] ?? '—')) ?></td>
                            <td><?= e((string) ($row['user_role'] ?? '')) ?></td>
                            <td><?= e((string) ($row['action'] ?? '')) ?></td>
                            <td><?= e((string) ($row['module'] ?? '')) ?></td>
                            <td><?= e($status) ?></td>
                            <td><?= e($anomaly) ?></td>
                            <td><?= e((string) ($row['ip_address'] ?? '')) ?></td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
        </div>
    <?php } ?>
</section>
<?php
layout_footer();
