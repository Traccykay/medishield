const { test, expect } = require('@playwright/test');
const { execFileSync } = require('node:child_process');
const { loginWithOtp, logout, resetUiDatabase, seedDashboardData } = require('./helpers');

// This helper can touch only the established disposable browser-test database.
function sql(statement) {
  return execFileSync('mysql.exe', ['--host=127.0.0.1', '--user=root',
    '--database=medishield_ui_test', '--batch', '--skip-column-names', '--raw',
    `--execute=${statement}`], { encoding: 'utf8' }).trim();
}

test.describe.configure({ mode: 'serial' });
test.beforeEach(() => resetUiDatabase());

test('emergency access requires reauthentication, is read-only, and admin revocation ends access', async ({ page, browser }) => {
  sql("INSERT INTO patients (patient_number, full_name, date_of_birth, gender, created_at) VALUES ('MSH-1111222233334444', 'Emergency Protected Patient', '1990-01-01', 'female', UTC_TIMESTAMP())");
  const patientId = sql("SELECT patient_id FROM patients WHERE patient_number='MSH-1111222233334444'");
  await loginWithOtp(page, 'ui.doctor@medishield.test');
  await page.goto('/doctor/emergency_access.php');
  const rejected = await page.request.post('/doctor/emergency_access.php', {
    form: { patient_number: 'MSH-1111222233334444', password: 'UiTest!2026A', reason: 'Urgent assessment' }
  });
  expect(rejected.status()).toBe(403);
  expect(sql('SELECT COUNT(*) FROM emergency_access_grants')).toBe('0');
  await page.getByLabel('Exact patient number').fill('MSH-1111222233334444');
  await page.getByLabel('Why emergency access is necessary').fill('Urgent assessment while clinician unavailable');
  await page.getByLabel('Confirm your password').fill('wrong');
  await page.getByRole('button', { name: 'Open temporary read-only access' }).click();
  await expect(page.getByText('Emergency access could not be granted.', { exact: false })).toBeVisible();
  expect(sql('SELECT COUNT(*) FROM emergency_access_grants')).toBe('0');
  await page.getByLabel('Exact patient number').fill('MSH-1111222233334444');
  await page.getByLabel('Why emergency access is necessary').fill('Urgent assessment while clinician unavailable');
  await page.getByLabel('Confirm your password').fill('UiTest!2026A');
  await page.getByRole('button', { name: 'Open temporary read-only access' }).click();
  await expect(page.getByText('Emergency Protected Patient', { exact: true })).toBeVisible();
  const chartUrl = page.url();
  const grantId = new URL(chartUrl).searchParams.get('grant_id');
  expect(grantId).not.toBeNull();
  expect(sql("SELECT COUNT(*) FROM audit_logs WHERE action='EMERGENCY_ACCESS_VIEWED'")).toBe('1');
  const wrongPatient = await page.request.get(`/doctor/emergency_chart.php?grant_id=${grantId}&patient_id=${Number(patientId) + 1}`);
  expect(wrongPatient.status()).toBe(403);
  expect(await wrongPatient.text()).not.toContain('Emergency Protected Patient');
  expect((await page.request.post(chartUrl, { form: {} })).status()).toBe(405);
  const normalChart = await page.request.get(`/doctor/view_patient.php?patient_id=${patientId}&visit_id=1`);
  expect(normalChart.status()).toBe(403);
  const csrf = await page.locator('input[name="csrf_token"]').first().inputValue();
  const mutation = await page.request.post('/doctor/add_diagnosis.php', {
    form: { csrf_token: csrf, patient_id: patientId, visit_id: '1', diagnosis: 'Forbidden' }
  });
  expect(mutation.status()).toBe(403);
  expect(sql('SELECT COUNT(*) FROM medical_records')).toBe('0');
  const adminContext = await browser.newContext();
  const admin = await adminContext.newPage();
  await loginWithOtp(admin, 'ui.admin@medishield.test');
  expect((await admin.request.get(chartUrl)).status()).toBe(403);
  await admin.goto('/admin/emergency_access.php');
  await expect(admin.getByText('1 grants awaiting review.', { exact: false })).toBeVisible();
  expect((await admin.request.post('/admin/emergency_access.php', { form: { grant_id: grantId, action: 'revoke' } })).status()).toBe(403);
  await admin.getByRole('link', { name: 'View reason' }).click();
  await expect(admin.getByText('Urgent assessment while clinician unavailable', { exact: true })).toBeVisible();
  await admin.getByRole('button', { name: 'Revoke and review' }).click();
  expect((await page.request.get(chartUrl)).status()).toBe(403);
  expect(sql('SELECT COUNT(*) FROM emergency_access_grants WHERE revoked_at IS NOT NULL AND reviewed_at IS NOT NULL')).toBe('1');
  await adminContext.close();
});

test('completed histories are personal while pending queues remain shared', async ({ page }) => {
  seedDashboardData();
  await loginWithOtp(page, 'ui.lab@medishield.test');
  await page.goto('/lab/history.php');
  await expect(page.locator('tbody tr')).toHaveCount(1);
  const ownLab = sql("SELECT user_id FROM users WHERE email='ui.lab@medishield.test'");
  sql("INSERT INTO users (full_name,email,password_hash,role,status,must_change_password,created_at,updated_at) SELECT 'Other Lab','other.lab@example.test',password_hash,'lab','active',0,UTC_TIMESTAMP(),UTC_TIMESTAMP() FROM users WHERE email='ui.lab@medishield.test'");
  const otherLab = sql("SELECT user_id FROM users WHERE email='other.lab@example.test'");
  await logout(page);
  await loginWithOtp(page, 'other.lab@example.test');
  await page.goto('/lab/history.php');
  await expect(page.getByText('No completed tests.')).toBeVisible();
  await page.goto('/lab/requests.php');
  expect(await page.locator('tbody tr').count()).toBeGreaterThan(0);
  // Existing completed order URLs cannot be used as an alternate history endpoint.
  const completedId = sql(`SELECT lr.lab_request_id FROM lab_requests lr JOIN lab_results r ON r.lab_request_id=lr.lab_request_id WHERE r.lab_technician_id=${ownLab} LIMIT 1`);
  const completed = await page.request.get(`/lab/upload_result.php?lab_request_id=${completedId}`, { maxRedirects: 0 });
  expect([303, 403]).toContain(completed.status());
  await logout(page);
  await loginWithOtp(page, 'ui.pharmacist@medishield.test');
  await page.goto('/pharmacy/history.php');
  expect(await page.locator('tbody tr').count()).toBeGreaterThan(0);
  sql("INSERT INTO users (full_name,email,password_hash,role,status,must_change_password,created_at,updated_at) SELECT 'Other Pharmacy','other.pharmacy@example.test',password_hash,'pharmacist','active',0,UTC_TIMESTAMP(),UTC_TIMESTAMP() FROM users WHERE email='ui.pharmacist@medishield.test'");
  await logout(page);
  await loginWithOtp(page, 'other.pharmacy@example.test');
  await page.goto('/pharmacy/history.php');
  await expect(page.getByText('No dispensed medication.')).toBeVisible();
  await page.goto('/pharmacy/prescriptions.php');
  expect(await page.locator('tbody tr').count()).toBeGreaterThan(0);
});

test('audit outage blocks PHI reads but preserves administrator integrity diagnostics', async ({ page }) => {
  seedDashboardData();
  await loginWithOtp(page, 'ui.admin@medishield.test');
  sql("REVOKE INSERT ON medishield_ui_test.audit_logs FROM 'medishield_app'@'127.0.0.1'");
  try {
    const records = await page.request.get('/patients.php');
    expect(records.status()).toBe(500);
    expect(await records.text()).not.toContain('patient_number');
    const diagnostic = await page.goto('/admin/audit.php');
    expect(diagnostic.status()).toBe(200);
    await expect(page.getByRole('heading', { name: 'Forensic auditing' })).toBeVisible();
    await expect(page.getByText('Audit logging is unavailable.', { exact: false })).toBeVisible();
    await expect(page.locator('tbody tr')).toHaveCount(0);
  } finally {
    sql("GRANT INSERT ON medishield_ui_test.audit_logs TO 'medishield_app'@'127.0.0.1'");
  }
});
