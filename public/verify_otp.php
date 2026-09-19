<?php

declare(strict_types=1);

/**
 * verify_otp.php
 * --------------
 * Second step of two-factor login. login.php verifies the email + password, issues
 * a one-time code, emails it, and stores a *pending* login in the session before
 * sending the user here. This page asks for that code and ONLY then completes the
 * login (calls login_user()).
 *
 * Security behaviour:
 *   - The user is NOT authenticated here — we read $_SESSION['pending_login'] (set
 *     server-side by login.php), never trusting any user id from the request.
 *   - CSRF token required on POST.
 *   - Generic messaging; the real verify status (invalid/expired/too_many) is
 *     audited (OTP_VERIFIED / OTP_FAILED / OTP_EXPIRED) but not leaked verbatim.
 *   - On too many wrong tries or an expired code the pending login is discarded and
 *     the user must start again — mirrors the OtpService contract.
 *   - Session id is regenerated on success inside login_user() (anti-fixation).
 */

use MediShield\Auth\Rbac;
use MediShield\Security\Csrf;

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';
ms_send_no_store_headers();

// Already fully logged in? Nothing to verify.
if (is_logged_in()) {
    $u = current_user();
    redirect($u['must_change'] ? '/change_password.php' : landing_path_for($u['role']));
}

$isPost = request_post_guard('auth');

// No pending login => the user came here directly or the step expired.
$pending = $_SESSION['pending_login'] ?? null;
if (!is_array($pending) || empty($pending['user_id'])) {
    redirect('/login.php');
}

$pendingResult = ms_session_validator()->validatePendingLogin($pending);
if ($pendingResult['status'] !== 'valid') {
    $candidateId = $pending['user_id'] ?? null;
    $candidateRole = $pending['role'] ?? null;
    $userId = is_int($candidateId) && $candidateId > 0 ? $candidateId : null;
    $role = is_string($candidateRole) && Rbac::isValidRole($candidateRole)
        ? $candidateRole
        : 'guest';
    if ($userId !== null) {
        ms_otp_service()->invalidateForUser($userId);
    }
    ms_audit_log([
        'user_id' => $userId,
        'user_role' => $role,
        'action' => $pendingResult['status'] === 'expired' ? 'OTP_EXPIRED' : 'OTP_FAILED',
        'module' => 'auth',
        'status' => $pendingResult['status'] === 'expired' ? 'FAILED' : 'BLOCKED',
        'anomaly_flag' => $pendingResult['status'] === 'malformed' ? 'SUSPICIOUS' : 'NORMAL',
    ]);
    unset($_SESSION['pending_login']);
    redirect($pendingResult['status'] === 'expired'
        ? '/login.php?otp=expired'
        : '/login.php?otp=revoked');
}

$authoritativeUser = (array) $pendingResult['user'];
$userId = (int) $authoritativeUser['user_id'];
$role   = (string) $authoritativeUser['role'];
$error  = null;

if ($isPost) {
    $code = strtoupper(trim(request_string($_POST['otp'] ?? null)));

    if (!ms_request_throttle()->allow(
        'otp_verify',
        ms_client_ip(),
        (int) (ms_config()['request_throttling']['otp_max_attempts'] ?? 60),
        (int) (ms_config()['request_throttling']['window_seconds'] ?? 900)
    )) {
        ms_audit_log([
            'user_id' => $userId,
            'user_role' => $role,
            'action' => 'OTP_FAILED',
            'module' => 'auth',
            'status' => 'BLOCKED',
            'anomaly_flag' => 'HIGH_RISK',
        ]);
        $error = 'Too many verification attempts. Please try again later.';
    } else {
        $status = ms_otp_service()->verify($userId, $code);

        if ($status === 'ok') {
            // Re-check the epoch after code consumption, closing the account-state
            // race between page load and OTP redemption.
            $finalPending = ms_session_validator()->validatePendingLogin($pending);
            if ($finalPending['status'] !== 'valid') {
                ms_audit_log([
                    'user_id' => $userId,
                    'user_role' => $role,
                    'action' => 'OTP_FAILED',
                    'module' => 'auth',
                    'status' => 'BLOCKED',
                ]);
                unset($_SESSION['pending_login']);
                redirect('/login.php?otp=revoked', 303);
            }
            $user = (array) $finalPending['user'];

            ms_audit_log([
                'user_id'   => $userId,
                'user_role' => (string) $user['role'],
                'action'    => 'OTP_VERIFIED',
                'module'    => 'auth',
                'status'    => 'SUCCESS',
            ]);

            unset($_SESSION['pending_login']);
            login_user($user);

            // LOGIN_SUCCESS is true only after MFA and session regeneration. If
            // this critical append fails, revoke the new session and require a
            // fresh sign-in; access remains fail closed.
            if (!ms_audit_log([
                'user_id' => $userId,
                'user_role' => (string) $user['role'],
                'action' => 'LOGIN_SUCCESS',
                'module' => 'auth',
                'status' => 'SUCCESS',
            ])) {
                logout_user();
                redirect('/login.php?otp=audit_unavailable', 303);
            }

            $mustChange = (bool) ($user['must_change_password'] ?? false);
            redirect(
                $mustChange ? '/change_password.php' : landing_path_for((string) $user['role']),
                303
            );
        }

        if ($status === 'expired') {
            ms_audit_log([
                'user_id'   => $userId,
                'user_role' => $role,
                'action'    => 'OTP_EXPIRED',
                'module'    => 'auth',
                'status'    => 'FAILED',
            ]);
            unset($_SESSION['pending_login']);
            redirect('/login.php?otp=expired', 303);
        }

        if ($status === 'too_many') {
            // The code is now dead. Force a fresh login. Flag as suspicious — this
            // can indicate someone guessing codes.
            ms_audit_log([
                'user_id'      => $userId,
                'user_role'    => $role,
                'action'       => 'OTP_FAILED',
                'module'       => 'auth',
                'status'       => 'FAILED',
                'anomaly_flag' => 'SUSPICIOUS',
            ]);
            unset($_SESSION['pending_login']);
            redirect('/login.php?otp=too_many', 303);
        }

        if ($status === 'none') {
            // No active code (e.g. a stale step). Restart cleanly.
            unset($_SESSION['pending_login']);
            redirect('/login.php', 303);
        }

        // 'invalid' — wrong code, attempt counted, user may retry.
        ms_audit_log([
            'user_id'   => $userId,
            'user_role' => $role,
            'action'    => 'OTP_FAILED',
            'module'    => 'auth',
            'status'    => 'FAILED',
        ]);
        $error = 'That code is not correct. Please check the code we emailed and try again.';
    }
}

$token = Csrf::token($_SESSION);

layout_header('Verify code');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Enter your code</h1>
    <p class="ms-muted">We emailed a one-time verification code to your address.
        Enter it below to finish signing in.</p>

    <?php if ($error !== null) { layout_alert('danger', $error); } ?>

    <form method="post" action="<?= e(ms_url('/verify_otp.php')) ?>" autocomplete="off" novalidate>
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">

        <label class="ms-label" for="otp">Verification code</label>
        <input class="ms-input" type="text" id="otp" name="otp"
               inputmode="latin" autocapitalize="characters" maxlength="12"
               required>
        <p class="ms-help">The code expires a few minutes after it is sent.</p>

        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Verify</button>
    </form>

    <p class="ms-mt"><a href="<?= e(ms_url('/login.php')) ?>">Start over</a></p>
</section>
<?php
layout_footer();
