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
use MediShield\Support\ListPage;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$admin = require_area('admin');
$isPost = request_post_guard('admin');

$errors  = [];
$success = null;
if (isset($_GET['reset'])) {
    $success = 'Password reset link sent to the user.';
}

if ($isPost) {
    $targetId  = request_positive_int($_POST['user_id'] ?? null);
    $newStatus = request_string($_POST['status'] ?? null);

    if (!in_array($newStatus, ['active', 'inactive'], true)) {
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

$query = trim(request_string($_GET['q'] ?? null));
$roleFilter = request_string($_GET['role'] ?? null);
$statusFilter = request_string($_GET['user_status'] ?? null);
$users = array_values(array_filter(ms_user_repo()->listAll(), static function (array $account) use ($query, $roleFilter, $statusFilter): bool {
    $needle = mb_strtolower($query);
    $matchesQuery = $needle === '' || str_contains(mb_strtolower((string) $account['full_name']), $needle)
        || str_contains(mb_strtolower((string) $account['email']), $needle);
    return $matchesQuery
        && ($roleFilter === '' || (string) $account['role'] === $roleFilter)
        && ($statusFilter === '' || (string) $account['status'] === $statusFilter);
}));
$userPage = ListPage::fromRows($users, $_GET['page'] ?? null, $_GET['per_page'] ?? null);
$users = $userPage['rows'];
$token = Csrf::token($_SESSION);

layout_app_header('Manage users', $admin, 'users');
?>
<section class="ms-card">
    <div class="ms-card-head">
        <h1 class="ms-h1">Manage users</h1>
        <a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/admin/create_user.php')) ?>">Create user</a>
    </div>

    <?php if ($success !== null) { layout_alert('success', $success); } ?>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>

    <form method="get" class="ms-filter-bar">
        <label class="ms-sr-only" for="user-search">Search users</label>
        <input class="ms-input" id="user-search" type="search" name="q" value="<?= e($query) ?>" placeholder="Search name or email">
        <label class="ms-sr-only" for="user-role">Role</label>
        <select class="ms-input" id="user-role" name="role"><option value="">All roles</option><?php foreach (['patient','receptionist','nurse','doctor','lab','pharmacist','admin'] as $role) { ?><option value="<?= e($role) ?>" <?= $roleFilter === $role ? 'selected' : '' ?>><?= e(ucfirst($role)) ?></option><?php } ?></select>
        <label class="ms-sr-only" for="user-status">Account status</label>
        <select class="ms-input" id="user-status" name="user_status"><option value="">All statuses</option><option value="active" <?= $statusFilter === 'active' ? 'selected' : '' ?>>Active</option><option value="inactive" <?= $statusFilter === 'inactive' ? 'selected' : '' ?>>Inactive</option></select>
        <label class="ms-sr-only" for="user-page-size">Results per page</label>
        <select class="ms-input" id="user-page-size" name="per_page"><?php foreach (ListPage::SIZES as $size) { ?><option value="<?= e((string) $size) ?>" <?= $userPage['per_page'] === $size ? 'selected' : '' ?>><?= e((string) $size) ?> per page</option><?php } ?></select>
        <button class="ms-btn ms-btn-primary" type="submit">Apply filters</button><a class="ms-btn" href="<?= e(ms_url('/admin/users.php')) ?>">Clear</a>
    </form>

    <?php if ($users === []) { ?>
        <p class="ms-muted">No users yet.</p>
    <?php } else { ?>
        <div class="ms-table-wrap">
            <table class="ms-table ms-table-users">
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
                                    <form method="post" action="<?= e(ms_url('/admin/users.php')) ?>" class="ms-inline-form">
                                        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
                                        <input type="hidden" name="user_id" value="<?= e((string) $u['user_id']) ?>">
                                        <input type="hidden" name="status" value="<?= e($toggle) ?>">
                                        <button class="ms-btn ms-btn-sm" type="submit"><?= e($label) ?></button>
                                    </form>
                                    <form method="post" action="<?= e(ms_url('/admin/reset_password.php')) ?>" class="ms-inline-form">
                                       <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
                                       <input type="hidden" name="user_id" value="<?= e((string) $u['user_id']) ?>">
                                       <button class="ms-btn ms-btn-sm" type="submit">Send password reset</button>
                                    </form>
                                <?php } ?>
                            </td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
        </div>
        <?php layout_pagination($userPage, '/admin/users.php', ['q' => $query, 'role' => $roleFilter, 'user_status' => $statusFilter]); ?>
    <?php } ?>
</section>
<?php
layout_app_footer();
