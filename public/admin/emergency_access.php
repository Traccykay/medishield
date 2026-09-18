<?php

declare(strict_types=1);

use MediShield\Security\Csrf;
use MediShield\Support\ActionConfirmation;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('admin');
$errors = [];
if (request_post_guard('admin')) {
    $grantId = request_positive_int($_POST['grant_id'] ?? null);
    $action = request_string($_POST['action'] ?? null);
    if ($grantId < 1 || !in_array($action, ['review', 'revoke'], true)) {
        deny_access($user, 'admin:emergency_review');
    }
    if (!ActionConfirmation::allows($action, $_POST['confirm_consequence'] ?? null)) {
        $errors[] = 'Confirm that you understand revocation immediately ends future chart access.';
    } else {
        ms_emergency_access()->review($user, $grantId, $action === 'revoke');
        redirect('/admin/emergency_access.php');
    }
}
$beforeId = request_positive_int($_GET['before_id'] ?? null) ?: PHP_INT_MAX;
$grants = ms_emergency_access()->reviewQueue($user, $beforeId);
$pending = ms_emergency_access()->pendingReviewCount($user);
$detailId = request_positive_int($_GET['grant_id'] ?? null);
$detail = $detailId > 0 ? ms_emergency_access()->reviewDetail($user, $detailId) : null;
layout_app_header('Emergency access review', $user, 'audit');
?>
<section class="ms-card">
    <h1 class="ms-h1">Emergency access review</h1>
    <p><?= e((string) $pending) ?> grants awaiting review. Check each reason against the care context.
        Revocation stops subsequent chart requests; it cannot remove information already viewed.</p>
    <?php foreach ($errors as $error) { layout_alert('danger', $error); } ?>
    <?php if ($detail !== null) { ?>
        <h2 class="ms-h2">Reason for grant #<?= e((string) $detail['grant_id']) ?></h2>
        <p><?= e((string) $detail['reason']) ?></p>
    <?php } ?>
    <div class="ms-table-wrap"><table class="ms-table">
        <thead><tr><th>Grant</th><th>Doctor ID</th><th>Patient ID</th><th>Expires (UTC)</th><th>State</th><th>Review</th></tr></thead>
        <tbody><?php foreach ($grants as $grant) { ?>
            <tr>
                <td><?= e((string) $grant['grant_id']) ?></td>
                <td><?= e((string) $grant['doctor_id']) ?></td>
                <td><?= e((string) $grant['patient_id']) ?></td>
                <td><?= e((string) $grant['expires_at']) ?></td>
                <td><?= e($grant['revoked_at'] !== null ? 'Revoked' : ($grant['authorized_at'] === null ? 'Not activated' : ($grant['expires_at'] <= ms_clock()->nowString() ? 'Expired' : 'Active'))) ?></td>
                <td>
                    <a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/admin/emergency_access.php?grant_id=' . (int) $grant['grant_id'])) ?>">View reason</a>
                    <?php if ($grant['reviewed_at'] !== null) { ?>
                        <span>Reviewed <?= e((string) $grant['reviewed_at']) ?> by #<?= e((string) $grant['reviewed_by']) ?></span>
                    <?php } ?>
                    <form method="post" class="ms-review-form">
                        <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e(Csrf::token($_SESSION)) ?>">
                        <input type="hidden" name="grant_id" value="<?= e((string) $grant['grant_id']) ?>">
                        <?php if ($grant['reviewed_at'] === null) { ?><button class="ms-btn ms-btn-sm" name="action" value="review">Mark reviewed</button><?php } ?>
                        <?php if ($grant['revoked_at'] === null) { ?><label class="ms-confirmation"><input type="checkbox" name="confirm_consequence" value="1"> <span>Confirm immediate revocation</span></label><button class="ms-btn ms-btn-sm" name="action" value="revoke">Revoke and review</button><?php } ?>
                    </form>
                </td>
            </tr>
        <?php } ?></tbody>
    </table></div>
    <?php if (count($grants) === 50) { ?><a href="<?= e(ms_url('/admin/emergency_access.php?before_id=' . (int) $grants[49]['grant_id'])) ?>">Older grants</a><?php } ?>
</section>
<?php layout_app_footer(); ?>
