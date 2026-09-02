<?php

declare(strict_types=1);

use MediShield\Auth\Rbac;
use MediShield\Clinical\ClinicalCatalog;
use MediShield\Security\Csrf;

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

$user = require_nav('payments');
$isStaff = in_array($user['role'], [Rbac::ROLE_ADMIN, Rbac::ROLE_RECEPTIONIST], true);
$visitId = (int) ($_GET['visit_id'] ?? $_POST['visit_id'] ?? 0);
$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Csrf::check($_SESSION, $_POST[Csrf::FIELD] ?? null)) {
        $errors[] = 'Your session has expired. Please try again.';
    } elseif (!$isStaff) {
        $errors[] = 'You are not authorized to change billing records.';
    } elseif ($visitId < 1) {
        $errors[] = 'Billing record was not found.';
    } elseif ((string) ($_POST['action'] ?? '') === 'add_charge') {
        $result = ms_billing_service()->addCatalogCharge(
            $visitId,
            $user,
            (string) ($_POST['charge_type'] ?? ''),
            (string) ($_POST['catalogue_item'] ?? ''),
            $_POST['quantity'] ?? null
        );
        $errors = $result['errors'];
        if ($result['ok']) {
            $success = 'Charge added.';
        }
    } elseif ((string) ($_POST['action'] ?? '') === 'record_payment') {
        $result = ms_billing_service()->recordPayment(
            $visitId,
            $user,
            (string) ($_POST['payment_method'] ?? ''),
            (string) ($_POST['payment_status'] ?? ''),
            (string) ($_POST['payment_reference'] ?? ''),
            (string) ($_POST['receipt_number'] ?? '')
        );
        $errors = $result['errors'];
        if ($result['ok']) {
            $success = 'Payment recorded.';
        }
    } else {
        $errors[] = 'Invalid billing action.';
    }
}

$token = Csrf::token($_SESSION);
layout_app_header($isStaff ? 'Billing and payments' : 'My billing', $user, 'payments');

if (!$isStaff) {
    $bills = ms_billing_service()->billsForPatientUser((int) $user['user_id']);
    ?>
    <section class="ms-card">
        <h1 class="ms-h1">My billing</h1>
        <p class="ms-muted">Your visit charges, payment status, and receipts.</p>
        <?php foreach ($errors as $error) { layout_alert('danger', $error); } ?>
        <?php if ($bills === []) { layout_alert('info', 'No billing records are linked to your account.'); } ?>
        <?php foreach ($bills as $bill) { ?>
            <section class="ms-card ms-mt">
                <h2 class="ms-h2"><?= e((string) $bill['patient_name']) ?> · Visit #<?= e((string) $bill['visit_id']) ?></h2>
                <p><strong>Payment status:</strong> <?= e((string) $bill['payment_status']) ?></p>
                <p><strong>Payment method:</strong> <?= e((string) $bill['payment_method']) ?><?php if ($bill['insurer'] !== null) { ?> · <?= e((string) $bill['insurer']) ?><?php } ?></p>
                <?php if ($bill['payment_reference'] !== null) { ?><p><strong>Payment reference:</strong> <?= e((string) $bill['payment_reference']) ?></p><?php } ?>
                <?php if ($bill['receipt_number'] !== null) { ?><p><strong>Receipt number:</strong> <?= e((string) $bill['receipt_number']) ?></p><?php } ?>
                <?php require __DIR__ . '/../includes/partials/bill_charges.php'; ?>
            </section>
        <?php } ?>
    </section>
    <?php
    layout_app_footer();
    return;
}

$visit = $visitId > 0 ? ms_billing_service()->visitForStaff($visitId, $user) : null;
$bill = $visit === null ? null : ms_billing_service()->billForStaffVisit($visitId, $user);
$visits = ms_billing_service()->visitsForStaff($user);
?>
<section class="ms-card">
    <h1 class="ms-h1">Billing and payments</h1>
    <p class="ms-muted">Select a visit to add catalogue charges or record its cash or insurance payment.</p>
    <?php foreach ($errors as $error) { layout_alert('danger', $error); } ?>
    <?php if ($success !== '') { layout_alert('success', $success); } ?>

    <?php if ($visit === null) { ?>
        <table class="ms-table">
            <thead><tr><th>Patient</th><th>Visit status</th><th>Method</th><th>Total</th><th>Payment</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($visits as $listedVisit) { ?>
                <tr>
                    <td><?= e((string) $listedVisit['patient_name']) ?> <span class="ms-muted"><?= e((string) $listedVisit['patient_number']) ?></span></td>
                    <td><?= e((string) $listedVisit['status']) ?></td>
                    <td><?= e((string) $listedVisit['payment_method']) ?></td>
                    <td>KES <?= e(number_format((int) $listedVisit['total_amount'])) ?></td>
                    <td><?= e((string) ($listedVisit['payment_status'] ?? 'unbilled')) ?></td>
                    <td><a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/payments.php?visit_id=' . (int) $listedVisit['visit_id'])) ?>">Manage billing</a></td>
                </tr>
            <?php } ?>
            <?php if ($visits === []) { ?><tr><td colspan="6">No visits are available for billing.</td></tr><?php } ?>
            </tbody>
        </table>
    <?php } else { ?>
        <div class="ms-actions"><a class="ms-btn" href="<?= e(ms_url('/payments.php')) ?>">Back to visits</a></div>
        <section class="ms-card ms-mt">
            <h2 class="ms-h2">Manage visit billing</h2>
            <p class="ms-muted"><?= e((string) $visit['patient_name']) ?> · <?= e((string) $visit['patient_number']) ?></p>
            <p><strong>Visit payment method:</strong> <?= e((string) $visit['payment_method']) ?><?php if ($visit['insurer'] !== null) { ?> · <?= e((string) $visit['insurer']) ?><?php } ?></p>

            <?php if ($bill !== null) { ?>
                <p><strong>Payment status:</strong> <?= e((string) $bill['payment_status']) ?></p>
                <?php if ($bill['payment_reference'] !== null) { ?><p><strong>Payment reference:</strong> <?= e((string) $bill['payment_reference']) ?></p><?php } ?>
                <?php if ($bill['receipt_number'] !== null) { ?><p><strong>Receipt number:</strong> <?= e((string) $bill['receipt_number']) ?></p><?php } ?>
                <?php require __DIR__ . '/../includes/partials/bill_charges.php'; ?>
            <?php } else { ?>
                <p class="ms-muted">No charges have been added to this visit.</p>
            <?php } ?>

            <?php if ($bill === null || (string) $bill['payment_status'] !== 'paid') { ?>
                <form method="post" class="ms-mt">
                    <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
                    <input type="hidden" name="action" value="add_charge">
                    <input type="hidden" name="visit_id" value="<?= e((string) $visitId) ?>">
                    <label class="ms-label" for="charge_type">Charge type</label>
                    <select class="ms-input" id="charge_type" name="charge_type" required>
                        <option value="service">Service</option>
                        <option value="medication">Medication</option>
                    </select>
                    <label class="ms-label" for="catalogue_item">Catalogue item</label>
                    <select class="ms-input" id="catalogue_item" name="catalogue_item" required>
                        <optgroup label="Services">
                            <?php foreach (ClinicalCatalog::LAB_TESTS as $name => $price) { ?><option value="<?= e($name) ?>"><?= e($name) ?> · KES <?= e(number_format($price)) ?></option><?php } ?>
                        </optgroup>
                        <optgroup label="Medications">
                            <?php foreach (ClinicalCatalog::MEDICATIONS as $name => $price) { ?><option value="<?= e($name) ?>"><?= e($name) ?> · KES <?= e(number_format($price)) ?></option><?php } ?>
                        </optgroup>
                    </select>
                    <label class="ms-label" for="quantity">Quantity</label>
                    <input class="ms-input" id="quantity" name="quantity" type="number" min="1" max="100" value="1" required>
                    <button class="ms-btn ms-btn-primary ms-mt" type="submit">Add charge</button>
                </form>
            <?php } ?>

            <?php if ($bill !== null && $bill['charges'] !== [] && (string) $bill['payment_status'] !== 'paid') { ?>
                <form method="post" class="ms-mt">
                    <input type="hidden" name="<?= e(Csrf::FIELD) ?>" value="<?= e($token) ?>">
                    <input type="hidden" name="action" value="record_payment">
                    <input type="hidden" name="visit_id" value="<?= e((string) $visitId) ?>">
                    <input type="hidden" name="payment_method" value="<?= e((string) $bill['payment_method']) ?>">
                    <label class="ms-label" for="payment_status">Payment status</label>
                    <select class="ms-input" id="payment_status" name="payment_status" required>
                        <?php if ($bill['payment_method'] === 'insurance') { ?><option value="pending_insurance">Pending insurance</option><?php } ?>
                        <option value="paid">Paid</option>
                    </select>
                    <label class="ms-label" for="payment_reference">Payment reference</label>
                    <input class="ms-input" id="payment_reference" name="payment_reference" maxlength="100">
                    <label class="ms-label" for="receipt_number">Receipt number</label>
                    <input class="ms-input" id="receipt_number" name="receipt_number" maxlength="100">
                    <button class="ms-btn ms-btn-primary ms-mt" type="submit">Record payment</button>
                </form>
            <?php } ?>
        </section>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
