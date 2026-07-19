<?php

declare(strict_types=1);

use MediShield\Security\Csrf;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('nurse');
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $visitId = (int) ($_POST['visit_id'] ?? 0);
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $errors[] = 'Your session has expired. Please try again.';
    } else {
        $result = ms_visit_service()->moveToNurse($visitId, (int) $user['user_id']);
        if ($result['ok']) {
            $visit = ms_visit_repo()->findById($visitId);
            ms_audit_log(['user_id' => (int) $user['user_id'], 'user_role' => 'nurse', 'action' => 'ASSIGNMENT_CHANGED', 'module' => 'triage', 'affected_record_id' => (string) $visitId, 'status' => 'SUCCESS']);
            redirect('/nurse/add_vitals.php?patient_id=' . (int) $visit['patient_id'] . '&visit_id=' . $visitId);
        }
        $errors = $result['errors'];
    }
}
$queue = ms_visit_service()->triageQueue();
$token = Csrf::token($_SESSION);
layout_app_header('Triage queue', $user, 'dashboard');
?>
<section class="ms-card">
    <h1 class="ms-h1">Triage queue</h1>
    <p class="ms-muted">Claim the next patient, then record their vital signs and symptoms.</p>
    <?php foreach ($errors as $error) { layout_alert('danger', $error); } ?>
    <?php if ($queue === []) { ?><p class="ms-muted">No patients are waiting for triage.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table"><thead><tr><th>Patient</th><th>Patient #</th><th>Arrived (UTC)</th><th>Action</th></tr></thead><tbody>
        <?php foreach ($queue as $visit) { ?><tr><td><?= e((string) $visit['patient_name']) ?></td><td><?= e((string) $visit['patient_number']) ?></td><td><?= e((string) $visit['created_at']) ?></td><td><form class="ms-inline-form" method="post"><input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>"><input type="hidden" name="visit_id" value="<?= e((string) $visit['visit_id']) ?>"><button class="ms-btn ms-btn-sm ms-btn-primary" type="submit">Start triage</button></form></td></tr><?php } ?>
        </tbody></table></div>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
