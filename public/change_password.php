<?php

declare(strict_types=1);

/**
 * change_password.php
 * -------------------
 * Lets the signed-in user set a new password. This page serves two situations:
 *
 *   1. A FORCED change at first login. Admin-created accounts (including the
 *      seeded superadmin) start with must_change_password = 1, so guard.php
 *      redirects them here until they pick their own password.
 *   2. A VOLUNTARY change at any later time.
 *
 * Because of case (1) this is the one protected page that must remain reachable
 * while must_change_password is set, so it calls require_login() with
 * $allowPasswordChange = true to avoid an infinite redirect loop.
 *
 * Security behaviour (spec §11, §16, §17):
 *   - CSRF token required on POST.
 *   - The real work (verify current password, enforce policy, "must differ")
 *     lives in UserService::changePassword(); this page is thin glue.
 *   - Every attempt is audited as PASSWORD_RESET (SUCCESS / FAILED).
 *   - On success the must_change flag is cleared in the DB and in the session,
 *     then the user is sent to their normal landing page.
 */

use MediShield\Security\Csrf;

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

// Allow access even when must_change_password is set (that is the whole point).
$user = require_login(allowPasswordChange: true);

$errors = [];
$forced = (bool) $user['must_change'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $current = (string) ($_POST['current_password'] ?? '');
    $new     = (string) ($_POST['new_password'] ?? '');
    $confirm = (string) ($_POST['confirm_password'] ?? '');

    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        ms_audit_log([
            'user_id'      => (int) $user['user_id'],
            'user_role'    => (string) $user['role'],
            'action'       => 'CSRF_REJECTED',
            'module'       => 'auth',
            'status'       => 'BLOCKED',
            'anomaly_flag' => 'SUSPICIOUS',
        ]);
        $errors[] = 'Your session has expired. Please try again.';
    } elseif ($new !== $confirm) {
        // Cheap client-side-style check done server-side: confirmation must match.
        $errors[] = 'The new password and its confirmation do not match.';
    } else {
        $result = ms_user_service()->changePassword((int) $user['user_id'], $current, $new);

        if ($result['ok']) {
            ms_audit_log([
                'user_id'   => (int) $user['user_id'],
                'user_role' => (string) $user['role'],
                'action'    => 'PASSWORD_RESET',
                'module'    => 'auth',
                'status'    => 'SUCCESS',
            ]);

            // Reflect the cleared flag in the live session so guard.php stops
            // redirecting here on the next request.
            $_SESSION['auth']['must_change'] = false;

            redirect(landing_path_for($user['role']));
        }

        ms_audit_log([
            'user_id'   => (int) $user['user_id'],
            'user_role' => (string) $user['role'],
            'action'    => 'PASSWORD_RESET',
            'module'    => 'auth',
            'status'    => 'FAILED',
        ]);
        $errors = $result['errors'];
    }
}

$token = Csrf::token($_SESSION);

layout_header('Change password', $user);
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Change your password</h1>

    <?php if ($forced) { ?>
        <?php layout_alert('info', 'For your security you must set a new password before continuing.'); ?>
    <?php } ?>

    <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>

    <form method="post" action="/change_password.php" autocomplete="off" novalidate>
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">

        <label class="ms-label" for="current_password">Current password</label>
        <input class="ms-input" type="password" id="current_password" name="current_password" required autofocus>

        <label class="ms-label" for="new_password">New password</label>
        <input class="ms-input" type="password" id="new_password" name="new_password" required>
        <p class="ms-help">Use at least 12 characters with upper- and lower-case letters, a number and a symbol.</p>

        <label class="ms-label" for="confirm_password">Confirm new password</label>
        <input class="ms-input" type="password" id="confirm_password" name="confirm_password" required>

        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Update password</button>
    </form>
</section>
<?php
layout_footer();
