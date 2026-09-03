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
 *   - Lockout and anomaly flags come from AuthService; every account-state failure
 *     surfaces the same generic message while the audit retains the real outcome.
 *   - Every attempt is written to the forensic audit log (SUCCESS / FAILED),
 *     carrying the anomaly flag the service computed.
 *   - Session id is regenerated on success (handled in login_user()).
 */

use MediShield\Security\Csrf;

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';
ms_send_no_store_headers();

// Already authenticated? Skip the form.
if (is_logged_in()) {
    $u = current_user();
    redirect($u['must_change'] ? '/change_password.php' : landing_path_for($u['role']));
}

$isPost = request_post_guard('auth');
$error  = null;
$email  = '';
$notice = isset($_GET['timeout']) ? 'Your session expired. Please log in again.' : null;
$otpNotice = request_string($_GET['otp'] ?? null);
$passwordNotice = request_string($_GET['password'] ?? null);
if ($otpNotice === 'expired') {
    $notice = 'Your verification code expired. Please sign in again to get a new one.';
} elseif ($otpNotice === 'too_many') {
    $notice = 'Too many incorrect codes were entered. Please sign in again.';
} elseif ($otpNotice === 'revoked') {
    $notice = 'Your sign-in state changed. Please sign in again.';
} elseif ($passwordNotice === 'changed') {
    $notice = 'Your password was changed. Sign in again to continue.';
}

if ($isPost) {
    unset($_SESSION['pending_login']);
    $email    = trim(request_string($_POST['email'] ?? null));
    $password = request_string($_POST['password'] ?? null);

    if (!ms_request_throttle()->allow(
        'login',
        ms_client_ip(),
        (int) (ms_config()['request_throttling']['login_max_attempts'] ?? 100),
        (int) (ms_config()['request_throttling']['window_seconds'] ?? 900)
    )) {
        ms_audit_log([
            'user_role' => 'guest',
            'action' => 'LOGIN_FAILED',
            'module' => 'auth',
            'status' => 'BLOCKED',
            'anomaly_flag' => 'HIGH_RISK',
            'attempted_identifier' => $email !== '' ? $email : null,
        ]);
        $error = 'Too many sign-in attempts. Please try again later.';
    } else {
        $result = ms_auth()->attemptLogin($email, $password);

        if ($result['status'] === 'success') {
            $user = $result['user'];

            if (($result['account_unlocked'] ?? false) === true) {
                ms_audit_log([
                    'user_id' => (int) $user['user_id'],
                    'user_role' => (string) $user['role'],
                    'action' => 'ACCOUNT_UNLOCKED',
                    'module' => 'auth',
                    'status' => 'SUCCESS',
                ]);
            }

            // Password was correct, but LOGIN_SUCCESS is intentionally not emitted:
            // login is NOT complete yet because MediShield uses
            // email OTP as a second factor (2FA). We issue a one-time code, email it,
            // and stash a *pending* login in the session — distinct from the real
            // $_SESSION['auth'], so the user is NOT yet authenticated. They must pass
            // verify_otp.php before login_user() runs. (Lockout/failed-login tracking
            // already happened above in AuthService and is untouched by this stage.)
            $code = ms_otp_service()->issue((int) $user['user_id']);

            ms_mailer()->send(
                (string) $user['email'],
                (string) $user['full_name'],
                'Your MediShield verification code',
                "Hello " . (string) $user['full_name'] . ",\n\n"
                . "Your MediShield one-time verification code is: " . $code . "\n\n"
                . "It expires in " . (int) (ms_config()['otp']['ttl_minutes'] ?? 10)
                . " minutes. If you did not try to sign in, please tell an administrator.\n"
            );

            ms_audit_log([
                'user_id'   => (int) $user['user_id'],
                'user_role' => (string) $user['role'],
                'action'    => 'OTP_SENT',
                'module'    => 'auth',
                'status'    => 'SUCCESS',
            ]);

            // Only non-sensitive routing data lives in the pending record.
            $_SESSION['pending_login'] = ms_session_validator()->createPendingLogin($user);

            redirect('/verify_otp.php');
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
            'action'       => (string) ($result['audit_action'] ?? 'LOGIN_FAILED'),
            'module'       => 'auth',
            'status'       => 'FAILED',
            'anomaly_flag' => (string) ($result['anomaly'] ?? 'NORMAL'),
            // Always record the typed email — including for unknown accounts, where
            // it is the ONLY identifier we have. It is stored as PII outside the
            // hash chain and removed after the retention window
            // (scripts/purge-audit-pii.php).
            'attempted_identifier' => $email !== '' ? $email : null,
        ]);

        $error = 'Invalid email or password.';
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
        <p class="ms-mt"><a href="<?= e(ms_url('/forgot_password.php')) ?>">Forgot password?</a></p>
    </form>
</section>
<?php
layout_footer();
