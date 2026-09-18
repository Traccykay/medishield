<?php

declare(strict_types=1);

use MediShield\Support\ListPage;

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('lab');
$requests = ms_clinical_repo()->labRequests('pending');
$query = trim(request_string($_GET['q'] ?? null));
if ($query !== '') {
    $needle = mb_strtolower($query);
    $requests = array_values(array_filter($requests, static fn (array $row): bool =>
        str_contains(mb_strtolower((string) $row['test_name']), $needle)
        || str_contains(mb_strtolower((string) $row['patient_number']), $needle)
        || str_contains(mb_strtolower((string) $row['patient_name']), $needle)));
}
$requestPage = ListPage::fromRows($requests, $_GET['page'] ?? null, $_GET['per_page'] ?? null);
$requests = $requestPage['rows'];

ms_audit_read($user, 'lab.requests', array_column($requests, 'patient_id'));
layout_app_header('Lab requests', $user, 'reports');
?>
<section class="ms-card">
    <h1 class="ms-h1">Pending lab requests</h1>
    <form method="get" class="ms-filter-bar"><label class="ms-sr-only" for="lab-search">Search lab requests</label><input class="ms-input" id="lab-search" type="search" name="q" value="<?= e($query) ?>" placeholder="Test, patient name, or patient number"><label class="ms-sr-only" for="lab-page-size">Results per page</label><select class="ms-input" id="lab-page-size" name="per_page"><?php foreach (ListPage::SIZES as $size) { ?><option value="<?= e((string) $size) ?>" <?= $requestPage['per_page'] === $size ? 'selected' : '' ?>><?= e((string) $size) ?> per page</option><?php } ?></select><button class="ms-btn ms-btn-primary" type="submit">Apply</button><a class="ms-btn" href="<?= e(ms_url('/lab/requests.php')) ?>">Clear</a></form>
    <?php if ($requests === []) { ?><p class="ms-muted">No pending lab requests.</p><?php } else { ?>
        <div class="ms-table-wrap"><table class="ms-table">
            <thead><tr><th>Test</th><th>Patient #</th><th>Name</th><th>DOB</th><th>Gender</th><th>Doctor</th><th>Action</th></tr></thead>
            <tbody><?php foreach ($requests as $request) { ?><tr>
                <td><?= e((string) $request['test_name']) ?></td>
                <td><?= e((string) $request['patient_number']) ?></td>
                <td><?= e((string) $request['patient_name']) ?></td>
                <td><?= e((string) $request['date_of_birth']) ?></td>
                <td><?= e((string) $request['gender']) ?></td>
                <td><?= e((string) $request['doctor_name']) ?></td>
                <td><a class="ms-btn ms-btn-sm" href="<?= e(ms_url('/lab/upload_result.php?lab_request_id=' . (int) $request['lab_request_id'])) ?>">Upload result</a></td>
            </tr><?php } ?></tbody>
        </table></div>
        <?php layout_pagination($requestPage, '/lab/requests.php', ['q' => $query]); ?>
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
