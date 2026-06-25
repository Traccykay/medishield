<?php

declare(strict_types=1);

/**
 * admin/users.php
 * ---------------
 * The administrator's user-management list (spec §6.6, §25). Lists every account
 * and lets the admin activate or deactivate each one. Deactivated accounts cannot
 * log in (enforced by AuthService), which is how an admin disables access without
 * deleting forensic history.
 *
 * Gated by require_area('admin'). Status changes are POST-only and CSRF-protected
 * (never a GET link), so they cannot be triggered by a crafted URL or image tag.
 * Each change is audited as USER_UPDATED.
 *
 * An admin cannot deactivate their own account here — that guard prevents an admin
 * from accidentally locking the last person out of the admin area.
 */

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$admin = require_area('admin');

$errors  = [];
$success = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $targetId  = (int) ($_POST['user_id'] ?? 0);
    $newStatus = (string) ($_POST['status'] ?? '');

    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        ms_audit_log([
            'user_id'      => (int) $admin['user_id'],
            'user_role'    => (string) $admin['role'],
            'action'       => 'CSRF_REJECTED',
            'module'       => 'admin',
            'status'       => 'BLOCKED',
            'anomaly_flag' => 'SUSPICIOUS',
        ]);
        $errors[] = 'Your session has expired. Please try again.';
    } elseif (!in_array($newStatus, ['active', 'inactive'], true)) {
        $errors[] = 'Invalid status requested.';
    } elseif ($targetId === (int) $admin['user_id']) {
        // Self-lockout guard: you cannot deactivate the account you are using.
        $errors[] = 'You cannot change the status of your own account.';
    } else {
        $target = ms_user_repo()->findById($targetId);
        if ($target === null) {
            $errors[] = 'That user no longer exists.';
        } else {
            ms_user_repo()->setStatus($targetId, $newStatus);
            ms_audit_log([
                'user_id'            => (int) $admin['user_id'],
                'user_role'          => (string) $admin['role'],
                'action'             => 'USER_UPDATED',
                'module'             => 'admin',
                'affected_record_id' => $targetId,
                'status'             => 'SUCCESS',
            ]);
            $success = 'User status updated.';
        }
    }
}

$users = ms_user_repo()->listAll();
$token = Csrf::token($_SESSION);

layout_header('Manage users', $admin);
?>
<section class="ms-card">
    <div class="ms-card-head">
        <h1 class="ms-h1">Manage users</h1>
        <a class="ms-btn ms-btn-primary" href="/admin/create_user.php">Create user</a>
    </div>

    <?php if ($success !== null) { layout_alert('success', $success); } ?>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>

    <?php if ($users === []) { ?>
        <p class="ms-muted">No users yet.</p>
    <?php } else { ?>
        <div class="ms-table-wrap">
            <table class="ms-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Must change</th>
                        <th>Created (UTC)</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $u) {
                        $isSelf  = (int) $u['user_id'] === (int) $admin['user_id'];
                        $status  = (string) $u['status'];
                        $toggle  = $status === 'active' ? 'inactive' : 'active';
                        $label   = $status === 'active' ? 'Deactivate' : 'Activate';
                    ?>
                        <tr>
                            <td><?= e((string) $u['user_id']) ?></td>
                            <td><?= e((string) $u['full_name']) ?></td>
                            <td><?= e((string) $u['email']) ?></td>
                            <td><?= e((string) $u['role']) ?></td>
                            <td>
                                <span class="ms-badge ms-badge-<?= $status === 'active' ? 'ok' : 'muted' ?>">
                                    <?= e($status) ?>
                                </span>
                            </td>
                            <td><?= ((int) $u['must_change_password'] === 1) ? 'yes' : 'no' ?></td>
                            <td><?= e((string) $u['created_at']) ?></td>
                            <td>
                                <?php if ($isSelf) { ?>
                                    <span class="ms-muted">(you)</span>
                                <?php } else { ?>
                                    <form method="post" action="/admin/users.php" class="ms-inline-form">
                                        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
                                        <input type="hidden" name="user_id" value="<?= e((string) $u['user_id']) ?>">
                                        <input type="hidden" name="status" value="<?= e($toggle) ?>">
                                        <button class="ms-btn ms-btn-sm" type="submit"><?= e($label) ?></button>
                                    </form>
                                <?php } ?>
                            </td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
        </div>
    <?php } ?>
</section>
<?php
layout_footer();
