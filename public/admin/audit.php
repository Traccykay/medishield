<?php

declare(strict_types=1);

/**
 * admin/audit.php
 * ---------------
 * The "Forensic Auditing" page (spec §6.6). This is the dedicated home of the
 * forensic audit log, moved here from the admin dashboard so monitoring has its own
 * focused screen reachable from the sidebar.
 *
 * Gated by require_area('admin'): only administrators may view audit logs. Viewing
 * the log is itself an auditable event, so we record AUDIT_LOGS_VIEWED on each load.
 *
 * This page only READS the log (recent() + verifyChain()); there is deliberately no
 * code path that edits or deletes audit rows — even an admin cannot tamper with the
 * forensic record.
 */

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('admin');

// Record that the audit log was viewed (accountability for the monitors too).
ms_audit_log([
    'user_id'   => (int) $user['user_id'],
    'user_role' => (string) $user['role'],
    'action'    => 'AUDIT_LOGS_VIEWED',
    'module'    => 'admin',
    'status'    => 'SUCCESS',
]);

// Read-only views that must never take the page down.
$recent    = [];
$integrity = ['ok' => true, 'first_bad_log_id' => null];
try {
    $recent    = ms_audit()->recent(100);
    $integrity = ms_audit()->verifyChain();
} catch (\Throwable $e) {
    error_log('[admin/audit] audit read failed: ' . $e->getMessage());
}

layout_app_header('Forensic Auditing', $user, 'audit');
?>
<section class="ms-card">
    <div class="ms-card-head">
        <div>
            <h1 class="ms-h1">Forensic auditing</h1>
            <p class="ms-muted">Tamper-evident record of security activity: logins,
                failed attempts, OTP and activation events, and access denials.</p>
        </div>
        <div class="ms-stat <?= $integrity['ok'] ? 'ms-stat-ok' : 'ms-stat-bad' ?>">
            <div class="ms-stat-num"><?= $integrity['ok'] ? 'OK' : 'TAMPERED' ?></div>
            <div class="ms-stat-label">Chain integrity</div>
        </div>
    </div>

    <?php if (!$integrity['ok']) {
        layout_alert('danger', 'Audit chain integrity check FAILED. The log may have been tampered with from log #'
            . (string) ($integrity['first_bad_log_id'] ?? '?') . '.');
    } ?>

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
                        <th>Attempted email</th>
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
                            <td><?= e((string) ($row['attempted_identifier'] ?? '—')) ?></td>
                            <td><?= e((string) ($row['ip_address'] ?? '')) ?></td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
        </div>
    <?php } ?>
</section>
<?php
layout_app_footer();
