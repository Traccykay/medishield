<?php

declare(strict_types=1);

/**
 * index.php
 * ---------
 * Entry point. Sends users where they belong:
 *   - not logged in        -> /login.php
 *   - must change password -> /change_password.php (handled by require_login)
 *   - otherwise            -> their role landing page
 *
 * No output of its own; it only routes.
 */

require_once __DIR__ . '/../includes/guard.php';

if (!is_logged_in()) {
    redirect('/login.php');
}

$user = require_login();                 // enforces timeout + must-change redirect
redirect(landing_path_for($user['role']));
