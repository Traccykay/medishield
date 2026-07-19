<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/guard.php';
require_once __DIR__ . '/../../includes/layout.php';

$user = require_area('lab');
$requests = ms_clinical_repo()->labRequests('pending');

layout_app_header('Lab requests', $user, 'reports');
?>
<section class="ms-card">
    <h1 class="ms-h1">Pending lab requests</h1>
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
    <?php } ?>
</section>
<?php layout_app_footer(); ?>
