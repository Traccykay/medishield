<?php

declare(strict_types=1);

/**
 * unauthorized.php
 * ----------------
 * The 403 page shown when an authenticated user tries to reach something their
 * role may not access. The blocked attempt is audited at the point of denial
 * (see deny_access() in guard.php); this page only informs the user.
 */

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

layout_access_denied(current_user());
