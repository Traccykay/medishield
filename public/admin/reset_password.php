<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';

$admin = require_area('admin');
$userId = (int) ($_POST['user_id'] ?? 0);
if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null) || $userId <= 0) {
    redirect('/admin/users.php');
}

$target = ms_user_repo()->findById($userId);
if ($target === null) {
    redirect('/admin/users.php');
}

$token = ms_activation_service()->issueFor($userId);
$link = rtrim((string) ms_config()['mail']['app_base_url'], '/') . '/activate.php?token=' . urlencode($token);
ms_mailer()->send(
    (string) $target['email'],
    (string) $target['full_name'],
    'Reset your MediShield password',
    "Hello " . $target['full_name'] . ",\n\nAn administrator requested a password reset. Set a new password here:\n\n" . $link
);
ms_audit_log(['user_id' => (int) $admin['user_id'], 'user_role' => 'admin', 'action' => 'PASSWORD_RESET', 'module' => 'admin', 'affected_record_id' => (string) $userId, 'status' => 'SUCCESS']);
redirect('/admin/users.php?reset=1');
