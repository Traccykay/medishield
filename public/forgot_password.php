<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';
ms_send_no_store_headers();

$isPost = request_post_guard('auth');
$message = null;
$email = '';
if ($isPost) {
    $email = trim(request_string($_POST['email'] ?? null));
    if (!ms_request_throttle()->allow(
        'password_reset',
        ms_client_ip(),
        (int) (ms_config()['request_throttling']['password_reset_max_attempts'] ?? 10),
        (int) (ms_config()['request_throttling']['window_seconds'] ?? 900)
    )) {
        ms_audit_log([
            'user_role' => 'guest',
            'action' => 'PASSWORD_RESET',
            'module' => 'auth',
            'status' => 'BLOCKED',
            'anomaly_flag' => 'HIGH_RISK',
            'attempted_identifier' => $email !== '' ? $email : null,
        ]);
        $message = 'Too many password-reset requests. Please try again later.';
    } else {
        $user = ms_user_repo()->findByEmail($email);
        if ($user !== null && (string) $user['status'] === 'active') {
            $token = ms_activation_service()->issueFor((int) $user['user_id']);
            $link = rtrim((string) ms_config()['mail']['app_base_url'], '/') . '/activate.php?token=' . urlencode($token);
            $ttlMinutes = (int) (ms_config()['password_reset']['ttl_minutes'] ?? 60);
            ms_mailer()->send(
                (string) $user['email'],
                (string) $user['full_name'],
                'Reset your MediShield password',
                "Open this link to set a new password:\n\n" . $link
                . "\n\nThis link expires in " . $ttlMinutes . " minutes."
            );
        }
        $message = 'If that email belongs to an active account, a password reset link has been sent.';
    }
}
$token = Csrf::token($_SESSION);
layout_header('Forgot password');
?>
<section class="ms-card ms-card-narrow">
    <h1 class="ms-h1">Forgot password</h1>
    <p class="ms-muted">Enter your email address to request a password reset link.</p>
    <?php if ($message !== null) { layout_alert('success', $message); } ?>
    <form method="post" action="<?= e(ms_url('/forgot_password.php')) ?>">
        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
        <label class="ms-label" for="email">Email</label>
        <input class="ms-input" id="email" name="email" type="email" value="<?= e($email) ?>" required>
        <button class="ms-btn ms-btn-primary ms-btn-block" type="submit">Send reset link</button>
    </form>
    <p class="ms-mt"><a href="<?= e(ms_url('/login.php')) ?>">Back to sign in</a></p>
</section>
<?php layout_footer(); ?>
