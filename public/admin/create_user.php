<?php

declare(strict_types=1);

/**
 * admin/create_user.php
 * ---------------------
 * The administrator "registration" form (spec §9.2). MediShield has NO public
 * self-registration: only an admin (e.g. the seeded superadmin) creates accounts
 * and assigns one of the six roles.
 *
 * Account-activation-link flow: the admin does NOT set a password. The account is
 * created PENDING (status 'inactive', no usable password) and an activation token
 * is emailed to the user. The user follows the link (activate.php), sets their own
 * password, and the account becomes active. This means a password is never typed by
 * the admin or transmitted second-hand.
 *
 * Gated by require_area('admin'). This page is thin glue that:
 *   - checks CSRF on POST,
 *   - calls UserService::createPendingUser(),
 *   - issues an activation token and emails the link,
 *   - audits USER_CREATED and ACTIVATION_SENT (or the failure),
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
        $result = ms_user_service()->createPendingUser($fullName, $email, $role);

        if ($result['ok']) {
            $newUserId = (int) $result['user_id'];

            ms_audit_log([
                'user_id'            => (int) $admin['user_id'],
                'user_role'          => (string) $admin['role'],
                'action'             => 'USER_CREATED',
                'module'             => 'admin',
                'affected_record_id' => $newUserId,
                'status'             => 'SUCCESS',
            ]);

            // Mint an activation token and email the link. The token is single-use
            // and time-limited (see ActivationService); only its hash is stored.
            $activationToken = ms_activation_service()->issueFor($newUserId);
            $baseUrl = rtrim((string) (ms_config()['mail']['app_base_url'] ?? ''), '/');
            $link = $baseUrl . '/activate.php?token=' . urlencode($activationToken);

            ms_mailer()->send(
                $email,
                $fullName,
                'Activate your MediShield account',
                "Hello " . $fullName . ",\n\n"
                . "An administrator has created a MediShield account for you.\n"
                . "To activate it and choose your password, open this link:\n\n"
                . $link . "\n\n"
                . "The link expires in " . (int) (ms_config()['activation']['ttl_hours'] ?? 48)
                . " hours. If you were not expecting this, you can ignore this email.\n"
            );

            ms_audit_log([
                'user_id'            => (int) $admin['user_id'],
                'user_role'          => (string) $admin['role'],
                'action'             => 'ACTIVATION_SENT',
                'module'             => 'admin',
                'affected_record_id' => $newUserId,
                'status'             => 'SUCCESS',
            ]);

            $success = 'User created. An activation link has been emailed so they can set their own password and activate the account.';
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

layout_app_header('Create user', $admin, 'users');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Create user</h1>
    <p class="ms-muted">Register a new account and assign its role. The user will
        receive an email link to activate the account and set their own password.</p>

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

        <p class="ms-help">No password is set here. The user chooses their own
            password when they activate via the emailed link.</p>

        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Create user</button>
    </form>

    <p class="ms-mt"><a href="<?= e(ms_url('/admin/users.php')) ?>">Back to user list</a></p>
</section>
<?php
layout_app_footer();
