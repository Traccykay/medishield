const { execFileSync } = require('node:child_process');
const { test, expect } = require('@playwright/test');
const {
  loginWithOtp,
  resetUiDatabase,
  seedDashboardData
} = require('./helpers');

const database = 'medishield_ui_test';
const scenarios = [
  {
    name: 'lab request',
    link: 'Request lab',
    triggerTable: 'lab_requests',
    recordTable: 'lab_requests',
    idColumn: 'lab_request_id',
    action: 'LAB_REQUESTED',
    controls: [
      { name: 'test_name', value: 'Blood glucose', type: 'select' },
      { name: 'reason', value: 'Routing failure lab PHI sentinel', type: 'text' }
    ],
    button: 'Send to lab queue',
    message: 'The lab request was saved, but the visit could not be routed. Please refresh the patient record before continuing.',
    path: '/doctor/request_lab.php'
  },
  {
    name: 'prescription',
    link: 'Issue prescription',
    triggerTable: 'prescriptions',
    recordTable: 'prescriptions',
    idColumn: 'prescription_id',
    action: 'PRESCRIPTION_ISSUED',
    controls: [
      { name: 'medication', value: 'Paracetamol 500 mg', type: 'select' },
      { name: 'dosage', value: 'Routing failure dosage PHI sentinel', type: 'text' },
      { name: 'instructions', value: 'Routing failure instructions PHI sentinel', type: 'text' }
    ],
    button: 'Send to pharmacy queue',
    message: 'The prescription was saved, but the visit could not be routed. Please refresh the patient record before continuing.',
    path: '/doctor/issue_prescription.php'
  },
  {
    name: 'consultation with a lab order',
    link: 'Add diagnosis',
    triggerTable: 'lab_requests',
    recordTable: 'medical_records',
    idColumn: 'record_id',
    action: 'DIAGNOSIS_ADDED',
    controls: [
      { name: 'diagnosis', value: 'Routing failure diagnosis PHI sentinel', type: 'text' },
      { name: 'treatment', value: 'Routing failure treatment PHI sentinel', type: 'text' },
      { name: 'lab_tests[]', value: 'Blood glucose', type: 'check' }
    ],
    button: 'Save consultation and selected orders',
    message: 'The consultation and selected orders were saved, but the visit could not be routed. Please refresh the patient record before continuing.',
    path: '/doctor/add_diagnosis.php'
  }
];

function mysql(sql) {
  return execFileSync('mysql.exe', [
    '--host=127.0.0.1',
    '--user=root',
    `--database=${database}`,
    '--batch',
    '--skip-column-names',
    '--raw',
    `--execute=${sql}`
  ], { encoding: 'utf8' }).trim();
}

function armPostInsertRevocation(table) {
  const trigger = `e2e_revoke_after_${table}`;
  mysql(`
    DROP TRIGGER IF EXISTS ${trigger};
    CREATE TRIGGER ${trigger}
    AFTER INSERT ON ${table}
    FOR EACH ROW
    DELETE FROM patient_assignments
     WHERE patient_id = NEW.patient_id
       AND staff_user_id = NEW.doctor_id
  `);
}

function routingFailureState(scenario, patientId, visitId) {
  const sql = `
    SELECT JSON_OBJECT(
      'orderExists', (
        SELECT COUNT(*)
          FROM ${scenario.recordTable}
         WHERE patient_id = ${patientId}
           AND visit_id = ${visitId}
           AND ${scenario.idColumn} = (
             SELECT CAST(affected_record_id AS UNSIGNED)
               FROM audit_logs
              WHERE action = '${scenario.action}'
              ORDER BY log_id DESC
              LIMIT 1
           )
      ),
      'triggerOrderCount', (
        SELECT COUNT(*)
          FROM ${scenario.triggerTable}
         WHERE patient_id = ${patientId}
           AND visit_id = ${visitId}
      ),
      'doctorId', (
        SELECT user_id
          FROM users
         WHERE email = 'ui.doctor@medishield.test'
         LIMIT 1
      ),
      'visitStatus', (
        SELECT status
          FROM visits
         WHERE visit_id = ${visitId}
      ),
      'assignmentCount', (
        SELECT COUNT(*)
          FROM patient_assignments
         WHERE patient_id = ${patientId}
           AND staff_user_id = (
             SELECT user_id
               FROM users
              WHERE email = 'ui.doctor@medishield.test'
              LIMIT 1
           )
      ),
      'successCount', (
        SELECT COUNT(*)
          FROM audit_logs
         WHERE action = '${scenario.action}'
      ),
      'successLogId', (
        SELECT log_id
          FROM audit_logs
         WHERE action = '${scenario.action}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'successUserId', (
        SELECT user_id
          FROM audit_logs
         WHERE action = '${scenario.action}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'successRole', (
        SELECT user_role
          FROM audit_logs
         WHERE action = '${scenario.action}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'successModule', (
        SELECT module
          FROM audit_logs
         WHERE action = '${scenario.action}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'successRecordId', (
        SELECT affected_record_id
          FROM audit_logs
         WHERE action = '${scenario.action}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'successStatus', (
        SELECT status
          FROM audit_logs
         WHERE action = '${scenario.action}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'successAnomaly', (
        SELECT anomaly_flag
          FROM audit_logs
         WHERE action = '${scenario.action}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialCount', (
        SELECT COUNT(*)
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
      ),
      'denialLogId', (
        SELECT log_id
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialUserId', (
        SELECT user_id
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialRole', (
        SELECT user_role
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialModule', (
        SELECT module
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialRecordId', (
        SELECT affected_record_id
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialStatus', (
        SELECT status
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialAnomaly', (
        SELECT anomaly_flag
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialIp', (
        SELECT ip_address
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialUserAgent', (
        SELECT user_agent
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      ),
      'denialAttemptedIdentifier', (
        SELECT attempted_identifier
          FROM audit_logs
         WHERE action = 'UNAUTHORIZED_ACCESS'
           AND affected_record_id = '${patientId}'
         ORDER BY log_id DESC
         LIMIT 1
      )
    )
  `;

  return JSON.parse(mysql(sql));
}

test.describe.configure({ mode: 'serial' });

test.beforeEach(() => {
  resetUiDatabase();
  seedDashboardData();
});

test.afterAll(() => {
  resetUiDatabase();
});

for (const scenario of scenarios) {
  test(`preserves a committed ${scenario.name} and safely audits routing revocation`, async ({ page }) => {
    await loginWithOtp(page, 'ui.doctor@medishield.test');
    const consultationRow = page.getByRole('row').filter({ hasText: 'UI Doctor Consultation' });
    await consultationRow.getByRole('link', { name: 'Open' }).click();

    const patientId = Number(new URL(page.url()).searchParams.get('patient_id'));
    const visitId = Number(new URL(page.url()).searchParams.get('visit_id'));
    expect(patientId).toBeGreaterThan(0);
    expect(visitId).toBeGreaterThan(0);

    await page.getByRole('link', { name: scenario.link }).click();
    armPostInsertRevocation(scenario.triggerTable);
    for (const input of scenario.controls) {
      const control = input.type === 'check'
        ? page.locator(`[name="${input.name}"][value="${input.value}"]`)
        : page.locator(`[name="${input.name}"]`);
      if (input.type === 'select') {
        await control.selectOption(input.value);
      } else if (input.type === 'check') {
        await control.check();
      } else {
        await control.fill(input.value);
      }
    }
    await page.getByRole('button', { name: scenario.button }).click();

    expect(new URL(page.url()).pathname).toBe(scenario.path);
    await expect(page.getByText(scenario.message)).toBeVisible();

    const state = routingFailureState(scenario, patientId, visitId);
    expect(state.orderExists).toBe(1);
    expect(state.triggerOrderCount).toBeGreaterThan(0);
    expect(state.visitStatus).toBe('with_doctor');
    expect(state.assignmentCount).toBe(0);

    expect(state.successCount).toBe(1);
    expect(state.successUserId).toBe(state.doctorId);
    expect(state.successRole).toBe('doctor');
    expect(state.successModule).toBe('doctor');
    expect(state.successStatus).toBe('SUCCESS');
    expect(state.successAnomaly).toBe('NORMAL');

    expect(state.denialCount).toBe(1);
    expect(state.denialUserId).toBe(state.doctorId);
    expect(state.denialRole).toBe('doctor');
    expect(state.denialModule).toBe('doctor');
    expect(state.denialRecordId).toBe(String(patientId));
    expect(state.denialStatus).toBe('BLOCKED');
    expect(state.denialAnomaly).toBe('HIGH_RISK');
    expect(state.successLogId).toBeLessThan(state.denialLogId);

    const persistedDenial = JSON.stringify({
      actor: state.denialUserId,
      role: state.denialRole,
      module: state.denialModule,
      patient: patientId,
      status: state.denialStatus,
      anomaly: state.denialAnomaly,
      ip: state.denialIp,
      userAgent: state.denialUserAgent,
      attemptedIdentifier: state.denialAttemptedIdentifier
    });
    for (const input of scenario.controls) {
      expect(persistedDenial).not.toContain(input.value);
    }
  });
}
