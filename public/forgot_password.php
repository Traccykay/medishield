<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

$message = null;
$email = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim((string) ($_POST['email'] ?? ''));
    if (Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $user = ms_user_repo()->findByEmail($email);
        if ($user !== null && (string) $user['status'] === 'active') {
            $token = ms_activation_service()->issueFor((int) $user['user_id']);
            $link = rtrim((string) ms_config()['mail']['app_base_url'], '/') . '/activate.php?token=' . urlencode($token);
            ms_mailer()->send((string) $user['email'], (string) $user['full_name'], 'Reset your MediShield password', "Open this link to set a new password:\n\n" . $link);
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
