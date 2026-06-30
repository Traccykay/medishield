<?php

declare(strict_types=1);

/**
 * activate.php
 * ------------
 * Account-activation landing page (guest). When an admin creates a user, an
 * activation link (activate.php?token=...) is emailed. The user opens it here,
 * chooses their own password, and the account is activated (status -> active).
 *
 * Security behaviour:
 *   - The token is high-entropy and looked up by its SHA-256 hash (never stored in
 *     plaintext); it is single-use and time-limited (see ActivationService).
 *   - The token is validated on GET before the form is shown, and re-validated on
 *     POST inside ActivationService::activate() — we never trust a user id from the
 *     request.
 *   - CSRF token required on POST; the activation token rides along as a hidden
 *     field so the same link survives the form submit.
 *   - The chosen password is checked against the same PasswordPolicy as every other
 *     password in the system.
 *   - ACCOUNT_ACTIVATED is written to the forensic audit log on success.
 */

use MediShield\Security\Csrf;

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

// A logged-in user has no business on the activation page.
if (is_logged_in()) {
    $u = current_user();
    redirect($u['must_change'] ? '/change_password.php' : landing_path_for($u['role']));
}

// The token arrives in the query string (GET) and is echoed back as a hidden field
// on POST so the form submit keeps the same activation token.
$tokenValue = (string) ($_POST['token'] ?? $_GET['token'] ?? '');

$errors  = [];
$success = false;
$valid   = false;

if ($tokenValue === '') {
    $errors[] = 'This activation link is missing its token.';
} else {
    $check = ms_activation_service()->validate($tokenValue);
    $valid = $check['ok'];
    if (!$valid) {
        $errors[] = $check['reason'] === 'expired'
            ? 'This activation link has expired. Please ask an administrator to resend it.'
            : 'This activation link is invalid or has already been used.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $tokenValue !== '') {
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        ms_audit_log([
            'user_role'    => 'guest',
            'action'       => 'CSRF_REJECTED',
            'module'       => 'auth',
            'status'       => 'BLOCKED',
            'anomaly_flag' => 'SUSPICIOUS',
        ]);
        $errors = ['Your session has expired. Please try again.'];
    } else {
        $password = (string) ($_POST['password'] ?? '');
        $confirm  = (string) ($_POST['confirm_password'] ?? '');

        $result = ms_activation_service()->activate($tokenValue, $password, $confirm);

        if ($result['ok']) {
            ms_audit_log([
                'user_id'            => (int) $result['user_id'],
                'user_role'          => 'user',
                'action'             => 'ACCOUNT_ACTIVATED',
                'module'             => 'auth',
                'affected_record_id' => (int) $result['user_id'],
                'status'             => 'SUCCESS',
            ]);
            $success = true;
        } else {
            $errors = $result['errors'];
            // Re-check validity so a still-good token keeps the form on screen.
            $valid = ms_activation_service()->validate($tokenValue)['ok'];
        }
    }
}

$token = Csrf::token($_SESSION);

layout_header('Activate account');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Activate your account</h1>

    <?php if ($success) { ?>
        <?php layout_alert('success', 'Your account is now active. You can sign in with your new password.'); ?>
        <p class="ms-mt"><a class="ms-btn ms-btn-primary" href="<?= e(ms_url('/login.php')) ?>">Go to sign in</a></p>
    <?php } else { ?>
        <p class="ms-muted">Choose a password to finish setting up your MediShield account.</p>

        <?php foreach ($errors as $msg) { layout_alert('danger', $msg); } ?>

        <?php if ($valid) { ?>
            <form method="post" action="<?= e(ms_url('/activate.php')) ?>" autocomplete="off" novalidate>
                <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
                <input type="hidden" name="token" value="<?= e($tokenValue) ?>">

                <label class="ms-label" for="password">New password</label>
                <input class="ms-input" type="password" id="password" name="password" required autofocus>
                <p class="ms-help">Minimum 12 characters with upper/lower case, a number and a symbol.</p>

                <label class="ms-label" for="confirm_password">Confirm password</label>
                <input class="ms-input" type="password" id="confirm_password" name="confirm_password" required>

                <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Activate account</button>
            </form>
        <?php } else { ?>
            <p class="ms-mt"><a href="<?= e(ms_url('/login.php')) ?>">Back to sign in</a></p>
        <?php } ?>
    <?php } ?>
</section>
<?php
layout_footer();
