<?php

declare(strict_types=1);

use MediShield\Reporting\ReportPeriod;

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
$period = ReportPeriod::resolve(
    request_string($_GET['period'] ?? 'today'),
    request_string($_GET['from'] ?? null),
    request_string($_GET['to'] ?? null),
    new DateTimeImmutable('now', new DateTimeZone('UTC'))
);
$doctorVisits = $role === 'doctor'
    ? ms_visit_service()->doctorVisits((int) $user['user_id'])
    : [];
$activityMetrics = ms_activity_reports()->forUserBetween(
    (int) $user['user_id'],
    $role,
    $period['start'],
    $period['end']
);
$report = match ($role) {
    'admin' => [
        'title' => 'Administrative report',
        'summary' => 'Current account and audit activity.',
        'metrics' => array_merge([
            'Active accounts' => count(array_filter(
                ms_user_repo()->listAll(),
                static fn (array $account): bool => ($account['status'] ?? '') === 'active'
            )),
            'Recent audit events' => count(ms_audit()->recent(25)),
        ], $activityMetrics),
    ],
    'receptionist' => [
        'title' => 'Reception activity report',
        'summary' => 'Your own registration and payment activity. No clinical information is included.',
        'metrics' => $activityMetrics,
    ],
    'patient' => [
        'title' => 'My service summary',
        'summary' => 'Counts of services linked to your account without displaying clinical contents.',
        'metrics' => $activityMetrics,
    ],
    'nurse' => [
        'title' => 'Nursing report',
        'summary' => 'Your active triage and recently recorded vital signs.',
        'metrics' => array_merge([
            'Patients in triage' => count(ms_visit_service()->nurseVisits((int) $user['user_id'])),
            'Recent vitals shown' => count(ms_clinical_repo()->recentVitalsByNurse((int) $user['user_id'])),
        ], $activityMetrics),
    ],
    'doctor' => [
        'title' => 'Clinical report',
        'summary' => 'Your workload and lifetime service counts. No patient identities or clinical contents are included.',
        'metrics' => array_merge([
            'Current consultations' => count($doctorVisits),
            'Pending lab requests' => ms_clinical_repo()->countLabRequestsByDoctor((int) $user['user_id']),
            'Pending prescriptions' => ms_clinical_repo()->countPrescriptionsByDoctor(
                (int) $user['user_id']
            ),
        ], $activityMetrics),
    ],
    'lab' => [
        'title' => 'Laboratory report',
        'summary' => 'Tests waiting for processing and completed tests.',
        'metrics' => array_merge([
            'Pending requests' => count(ms_clinical_repo()->labRequests('pending')),
            'Completed requests' => count(ms_clinical_repo()->completedByLabTechnician((int) $user['user_id'])),
        ], $activityMetrics),
    ],
    'pharmacist' => [
        'title' => 'Pharmacy report',
        'summary' => 'Prescriptions waiting for processing and dispensing history.',
        'metrics' => array_merge([
            'Pending prescriptions' => count(ms_clinical_repo()->prescriptions('pending')),
            'Dispensed prescriptions' => count(ms_clinical_repo()->dispensedByPharmacist((int) $user['user_id'])),
        ], $activityMetrics),
    ],
    default => [
        'title' => 'Operational report',
        'summary' => 'No report is available for this role.',
        'metrics' => [],
    ],
};

ms_audit_read($user, 'reports', []);
layout_app_header('Reports', $user, 'reports');
?>
<section class="ms-card">
    <h1 class="ms-h1"><?= e((string) $report['title']) ?></h1>
    <p class="ms-muted"><?= e((string) $report['summary']) ?></p>
    <form method="get" class="ms-filter-bar">
        <label class="ms-sr-only" for="report-period">Reporting period</label>
        <select class="ms-input" id="report-period" name="period"><option value="today" <?= $period['preset'] === 'today' ? 'selected' : '' ?>>Today</option><option value="week" <?= $period['preset'] === 'week' ? 'selected' : '' ?>>This week</option><option value="month" <?= $period['preset'] === 'month' ? 'selected' : '' ?>>This month</option><option value="custom" <?= $period['preset'] === 'custom' ? 'selected' : '' ?>>Custom range</option></select>
        <label class="ms-sr-only" for="report-from">From date</label>
        <input class="ms-input" id="report-from" type="date" name="from" value="<?= e(request_string($_GET['from'] ?? null)) ?>">
        <label class="ms-sr-only" for="report-to">To date</label>
        <input class="ms-input" id="report-to" type="date" name="to" value="<?= e(request_string($_GET['to'] ?? null)) ?>">
        <button class="ms-btn ms-btn-primary" type="submit">Update report</button>
    </form>
    <p class="ms-help">Reporting period: <?= e($period['label']) ?>. Current workload cards remain live.</p>
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
    <?php $maximum = max(1, ...array_values($report['metrics'])); ?>
    <section class="ms-card">
        <h2 class="ms-h2">Activity overview</h2>
        <div class="ms-report-chart">
        <?php foreach ($report['metrics'] as $label => $value) { ?>
            <div class="ms-report-row"><span><?= e((string) $label) ?></span><progress max="<?= e((string) $maximum) ?>" value="<?= e((string) $value) ?>"><?= e((string) $value) ?></progress><strong><?= e((string) $value) ?></strong></div>
        <?php } ?>
        </div>
    </section>
    <?php if (array_sum($report['metrics']) === 0) { ?>
        <?php layout_alert('info', 'No operational items currently require action.'); ?>
    <?php } ?>
<?php } ?>
<?php
layout_app_footer();
