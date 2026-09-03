<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
ms_send_no_store_headers();

$admin = require_area('admin');
request_post_guard('admin', postOnly: true);
$userId = request_positive_int($_POST['user_id'] ?? null);
if ($userId <= 0) {
    redirect('/admin/users.php', 303);
}

$target = ms_user_repo()->findById($userId);
if ($target === null || (string) $target['status'] !== 'active') {
    redirect('/admin/users.php', 303);
}

$token = ms_activation_service()->issueFor($userId);
$link = rtrim((string) ms_config()['mail']['app_base_url'], '/') . '/activate.php?token=' . urlencode($token);
$ttlMinutes = (int) (ms_config()['password_reset']['ttl_minutes'] ?? 60);
ms_mailer()->send(
    (string) $target['email'],
    (string) $target['full_name'],
    'Reset your MediShield password',
    "Hello " . $target['full_name']
    . ",\n\nAn administrator requested a password reset. Set a new password here:\n\n"
    . $link . "\n\nThis link expires in " . $ttlMinutes . " minutes."
);
ms_audit_log(['user_id' => (int) $admin['user_id'], 'user_role' => 'admin', 'action' => 'PASSWORD_RESET', 'module' => 'admin', 'affected_record_id' => (string) $userId, 'status' => 'SUCCESS']);
redirect('/admin/users.php?reset=1', 303);
