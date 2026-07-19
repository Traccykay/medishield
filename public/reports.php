<?php

declare(strict_types=1);

/**
 * reports.php
 * -----------
 * Role-scoped operational counts. The report exposes no clinical contents and
 * deliberately relies on the same RBAC-filtered queries as each workspace.
 */

require_once __DIR__ . '/../includes/guard.php';
require_once __DIR__ . '/../includes/layout.php';

$user = require_nav('reports');
$role = (string) $user['role'];
$report = match ($role) {
    'admin' => [
        'title' => 'Administrative report',
        'summary' => 'Current account and audit activity.',
        'metrics' => [
            'Active accounts' => count(array_filter(
                ms_user_repo()->listAll(),
                static fn (array $account): bool => ($account['status'] ?? '') === 'active'
            )),
            'Recent audit events' => count(ms_audit()->recent(25)),
        ],
    ],
    'nurse' => [
        'title' => 'Nursing report',
        'summary' => 'Your active triage and recently recorded vital signs.',
        'metrics' => [
            'Patients in triage' => count(ms_visit_service()->nurseVisits((int) $user['user_id'])),
            'Recent vitals shown' => count(ms_clinical_repo()->recentVitalsByNurse((int) $user['user_id'])),
        ],
    ],
    'doctor' => [
        'title' => 'Clinical report',
        'summary' => 'Your active consultations and outstanding orders.',
        'metrics' => [
            'Current consultations' => count(ms_visit_service()->doctorVisits((int) $user['user_id'])),
            'Pending lab requests' => count(ms_clinical_repo()->labRequests('pending', (int) $user['user_id'])),
            'Pending prescriptions' => count(ms_clinical_repo()->prescriptions('pending', (int) $user['user_id'])),
        ],
    ],
    'lab' => [
        'title' => 'Laboratory report',
        'summary' => 'Tests waiting for processing and completed tests.',
        'metrics' => [
            'Pending requests' => count(ms_clinical_repo()->labRequests('pending')),
            'Completed requests' => count(ms_clinical_repo()->labRequests('completed')),
        ],
    ],
    'pharmacist' => [
        'title' => 'Pharmacy report',
        'summary' => 'Prescriptions waiting for processing and dispensing history.',
        'metrics' => [
            'Pending prescriptions' => count(ms_clinical_repo()->prescriptions('pending')),
            'Dispensed prescriptions' => count(ms_clinical_repo()->prescriptions('dispensed')),
        ],
    ],
    default => [
        'title' => 'Operational report',
        'summary' => 'No report is available for this role.',
        'metrics' => [],
    ],
};

layout_app_header('Reports', $user, 'reports');
?>
<section class="ms-card">
    <h1 class="ms-h1"><?= e((string) $report['title']) ?></h1>
    <p class="ms-muted"><?= e((string) $report['summary']) ?></p>
</section>
<?php if ($report['metrics'] === []) { ?>
    <?php layout_alert('info', 'No report data is available for your role.'); ?>
<?php } else { ?>
    <section class="ms-grid">
        <?php foreach ($report['metrics'] as $label => $value) { ?>
            <div class="ms-card ms-stat">
                <div class="ms-stat-num"><?= e((string) $value) ?></div>
                <div class="ms-stat-label"><?= e((string) $label) ?></div>
            </div>
        <?php } ?>
    </section>
    <?php if (array_sum($report['metrics']) === 0) { ?>
        <?php layout_alert('info', 'No operational items currently require action.'); ?>
    <?php } ?>
<?php } ?>
<?php
layout_app_footer();
