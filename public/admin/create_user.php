<?php

declare(strict_types=1);

/**
 * admin/create_user.php
 * ---------------------
 * The administrator "registration" form (spec §9.2). MediShield has NO public
 * self-registration: only an admin (e.g. the seeded superadmin) creates accounts
 * and assigns one of the six roles. New accounts start with
 * must_change_password = 1, so the user sets their own password at first login.
 *
 * Gated by require_area('admin'). All creation logic, validation and password
 * policy live in UserService::createUser(); this page is thin glue that:
 *   - checks CSRF on POST,
 *   - calls the service,
 *   - audits USER_CREATED (SUCCESS) or the failure,
 *   - re-renders the form with field values + errors, or a success banner.
 */

use MediShield\Auth\Rbac;
use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$admin = require_area('admin');

$errors   = [];
$success  = null;
$fullName = '';
$email    = '';
$role     = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $fullName = trim((string) ($_POST['full_name'] ?? ''));
    $email    = trim((string) ($_POST['email'] ?? ''));
    $role     = (string) ($_POST['role'] ?? '');
    $password = (string) ($_POST['password'] ?? '');

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
    } else {
        $result = ms_user_service()->createUser($fullName, $email, $password, $role);

        if ($result['ok']) {
            ms_audit_log([
                'user_id'            => (int) $admin['user_id'],
                'user_role'          => (string) $admin['role'],
                'action'             => 'USER_CREATED',
                'module'             => 'admin',
                'affected_record_id' => (int) $result['user_id'],
                'status'             => 'SUCCESS',
            ]);
            $success = 'User created. They will be required to set their own password at first login.';
            // Clear the form for the next entry.
            $fullName = $email = $role = '';
        } else {
            ms_audit_log([
                'user_id'   => (int) $admin['user_id'],
                'user_role' => (string) $admin['role'],
                'action'    => 'USER_CREATED',
                'module'    => 'admin',
                'status'    => 'FAILED',
            ]);
            $errors = $result['errors'];
        }
    }
}

$token = Csrf::token($_SESSION);

layout_header('Create user', $admin);
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Create user</h1>
    <p class="ms-muted">Register a new account and assign its role.</p>

    <?php if ($success !== null) { layout_alert('success', $success); } ?>
    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>

    <form method="post" action="<?= e(ms_url('/admin/create_user.php')) ?>" autocomplete="off" novalidate>
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">

        <label class="ms-label" for="full_name">Full name</label>
        <input class="ms-input" type="text" id="full_name" name="full_name"
               value="<?= e($fullName) ?>" required autofocus>

        <label class="ms-label" for="email">Email</label>
        <input class="ms-input" type="email" id="email" name="email"
               value="<?= e($email) ?>" required>

        <label class="ms-label" for="role">Role</label>
        <select class="ms-input" id="role" name="role" required>
            <option value="">— select a role —</option>
            <?php foreach (Rbac::ROLES as $r) { ?>
                <option value="<?= e($r) ?>" <?= $role === $r ? 'selected' : '' ?>><?= e(ucfirst($r)) ?></option>
            <?php } ?>
        </select>

        <label class="ms-label" for="password">Temporary password</label>
        <input class="ms-input" type="password" id="password" name="password" required>
        <p class="ms-help">Minimum 12 characters with upper/lower case, a number and a symbol. The user must change it at first login.</p>

        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Create user</button>
    </form>

    <p class="ms-mt"><a href="<?= e(ms_url('/admin/users.php')) ?>">Back to user list</a></p>
</section>
<?php
layout_footer();
