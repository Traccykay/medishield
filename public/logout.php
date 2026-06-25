<?php

declare(strict_types=1);

/**
 * logout.php
 * ----------
 * Ends the session and returns to the login page. Audits the LOGOUT event for
 * the user who was signed in (if any) before tearing the session down.
 */

require_once __DIR__ . '/../includes/guard.php';

$user = current_user();
if ($user !== null) {
    ms_audit_log([
        'user_id'   => (int) $user['user_id'],
        'user_role' => (string) $user['role'],
        'action'    => 'LOGOUT',
        'module'    => 'auth',
        'status'    => 'SUCCESS',
    ]);
}

logout_user();
redirect('/login.php');
