<?php

declare(strict_types=1);

/**
 * login.php
 * ---------
 * Authenticates a user. GET renders the form; POST validates CSRF then delegates
 * to AuthService::attemptLogin() and, on success, establishes the session.
 *
 * Security behaviour (spec §11, §16, §17):
 *   - CSRF token required on POST.
 *   - Generic "Invalid email or password" message for every failure mode so the
 *     form never reveals whether an email exists (anti-enumeration).
 *   - Lockout and anomaly flags come from AuthService; we only surface a generic
 *     locked message and audit the real detail.
 *   - Every attempt is written to the forensic audit log (SUCCESS / FAILED),
 *     carrying the anomaly flag the service computed.
 *   - Session id is regenerated on success (handled in login_user()).
 */

use MediShield\Security\Csrf;

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

// Already authenticated? Skip the form.
if (is_logged_in()) {
    $u = current_user();
    redirect($u['must_change'] ? '/change_password.php' : landing_path_for($u['role']));
}

$error  = null;
$email  = '';
$notice = isset($_GET['timeout']) ? 'Your session expired. Please log in again.' : null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        // CSRF failure is itself a security event worth recording.
        ms_audit_log([
            'user_role'    => 'guest',
            'action'       => 'CSRF_REJECTED',
            'module'       => 'auth',
            'status'       => 'BLOCKED',
            'anomaly_flag' => 'SUSPICIOUS',
            // Capture the typed email (PII, retention-scrubbed) so an admin can see
            // which account a blocked attempt was aimed at.
            'attempted_identifier' => $email !== '' ? $email : null,
        ]);
        $error = 'Your session has expired. Please try again.';
    } else {
        $result = ms_auth()->attemptLogin($email, $password);

        if ($result['status'] === 'success') {
            $user = $result['user'];
            ms_audit_log([
                'user_id'   => (int) $user['user_id'],
                'user_role' => (string) $user['role'],
                'action'    => 'LOGIN_SUCCESS',
                'module'    => 'auth',
                'status'    => 'SUCCESS',
            ]);
            login_user($user);
            redirect($result['must_change'] ? '/change_password.php' : landing_path_for($user['role']));
        }

        // Any failure: audit with the computed anomaly flag, show a generic message.
        // When the email matched a real account we attribute the failed attempt to
        // that user (target_user_id/role) so an admin can follow up on a possible
        // credential compromise; an unknown email stays an anonymous 'guest' event.
        $targetId   = $result['target_user_id'] ?? null;
        $targetRole = $result['target_user_role'] ?? null;
        ms_audit_log([
            'user_id'      => $targetId,
            'user_role'    => $targetRole ?? 'guest',
            'action'       => 'LOGIN_FAILED',
            'module'       => 'auth',
            'status'       => 'FAILED',
            'anomaly_flag' => (string) ($result['anomaly'] ?? 'NORMAL'),
            // Always record the typed email — including for unknown accounts, where
            // it is the ONLY identifier we have. It is stored as PII outside the
            // hash chain and removed after the retention window
            // (scripts/purge-audit-pii.php).
            'attempted_identifier' => $email !== '' ? $email : null,
        ]);

        $error = $result['status'] === 'locked'
            ? 'This account is temporarily locked. Please try again later.'
            : 'Invalid email or password.';
    }
}

$token = Csrf::token($_SESSION);

layout_header('Login');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Sign in</h1>
    <p class="ms-muted">MediShield secure healthcare records</p>

    <?php if ($notice !== null) { layout_alert('info', $notice); } ?>
    <?php if ($error !== null) { layout_alert('danger', $error); } ?>

    <form method="post" action="<?= e(ms_url('/login.php')) ?>" autocomplete="off" novalidate>
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">

        <label class="ms-label" for="email">Email</label>
        <input class="ms-input" type="email" id="email" name="email"
               value="<?= e($email) ?>" required autofocus>

        <label class="ms-label" for="password">Password</label>
        <input class="ms-input" type="password" id="password" name="password" required>

        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Sign in</button>
    </form>
</section>
<?php
layout_footer();
