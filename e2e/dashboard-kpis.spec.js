const { execFileSync } = require('node:child_process');
const path = require('node:path');
const { test, expect } = require('@playwright/test');
const { loginWithOtp, logout } = require('./helpers');

const root = path.resolve(__dirname, '..');

function resetUiDatabase() {
  execFileSync('powershell.exe', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', path.join(root, 'scripts', 'setup-ui-test-db.ps1')
  ], { cwd: root, stdio: 'inherit' });
  execFileSync('php', [path.join(root, 'scripts', 'seed-ui-test-users.php')], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, MEDISHIELD_DB_NAME: 'medishield_ui_test' }
  });
}

test.describe.configure({ mode: 'serial' });

test.beforeEach(() => {
  resetUiDatabase();
});

test.afterAll(() => {
  resetUiDatabase();
});

test('role dashboards retain useful empty states before work begins', async ({ page }) => {
  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await expect(page.getByTestId('reception-triage-count')).toHaveText('0');
  await expect(page.getByText('No patients waiting.')).toBeVisible();

  await logout(page);
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  await expect(page.getByTestId('nurse-triage-count')).toHaveText('0');
  await expect(page.getByTestId('nurse-vitals-count')).toHaveText('0');
  await expect(page.getByText('No assigned patients yet.')).toBeVisible();

  await logout(page);
  await loginWithOtp(page, 'ui.patient@medishield.test');
  await expect(page.getByText('No patient record is linked to your login yet. Please contact the administrator.')).toBeVisible();
});

test('role dashboards show isolated workflow KPIs from real records', async ({ page }) => {
  await page.goto('/login.php');
  execFileSync('php', [path.join(root, 'scripts', 'seed-ui-dashboard-data.php')], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, MEDISHIELD_DB_NAME: 'medishield_ui_test' }
  });

  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await expect(page.getByTestId('reception-triage-count')).toHaveText('1');

  await logout(page);
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  await expect(page.getByTestId('nurse-triage-count')).toHaveText('1');
  await expect(page.getByTestId('nurse-vitals-count')).toHaveText('1');

  await logout(page);
  await loginWithOtp(page, 'ui.doctor@medishield.test');
  await expect(page.getByTestId('doctor-consultations-count')).toHaveText('1');
  await expect(page.getByTestId('doctor-pending-labs-count')).toHaveText('1');
  await expect(page.getByTestId('doctor-pending-prescriptions-count')).toHaveText('1');
  await page.goto('/reports.php');
  await expect(
    page.locator('.ms-stat').filter({ hasText: 'Pending lab requests' }).locator('.ms-stat-num')
  ).toHaveText('1');
  await expect(
    page.locator('.ms-stat').filter({ hasText: 'Pending prescriptions' }).locator('.ms-stat-num')
  ).toHaveText('1');

  await logout(page);
  await loginWithOtp(page, 'ui.lab@medishield.test');
  await expect(page.getByTestId('lab-pending-count')).toHaveText('1');
  await expect(page.getByTestId('lab-completed-count')).toHaveText('1');

  await logout(page);
  await loginWithOtp(page, 'ui.pharmacist@medishield.test');
  await expect(page.getByTestId('pharmacy-pending-count')).toHaveText('1');
  await expect(page.getByTestId('pharmacy-dispensed-count')).toHaveText('1');
  await expect(page.getByTestId('pharmacy-pending-total')).toHaveText('KES 150');

  await logout(page);
  await loginWithOtp(page, 'ui.patient@medishield.test');
  await expect(page.getByTestId('patient-vitals-count')).toHaveText('1');
  await expect(page.getByTestId('patient-records-count')).toHaveText('1');
  await expect(page.getByTestId('patient-lab-results-count')).toHaveText('1');
  await expect(page.getByTestId('patient-prescriptions-count')).toHaveText('1');

  await logout(page);
  await loginWithOtp(page, 'ui.admin@medishield.test');
  await expect(page.getByTestId('admin-active-users-count')).toHaveText(/^[1-9]\d*$/);
  await expect(page.getByTestId('admin-recent-audit-count')).not.toHaveText('0');
});

test('doctor patient view links to history and records one safe audit per page', async ({ page }) => {
  await page.goto('/login.php');
  execFileSync('php', [path.join(root, 'scripts', 'seed-ui-dashboard-data.php')], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, MEDISHIELD_DB_NAME: 'medishield_ui_test' }
  });

  await loginWithOtp(page, 'ui.doctor@medishield.test');
  const consultationRow = page.getByRole('row').filter({ hasText: 'UI Doctor Consultation' });
  await consultationRow.getByRole('link', { name: 'Open' }).click();
  const patientId = new URL(page.url()).searchParams.get('patient_id');
  const visitId = new URL(page.url()).searchParams.get('visit_id');
  expect(patientId).not.toBeNull();
  expect(visitId).not.toBeNull();
  await expect(page.getByText('Doctor audit privacy sentinel')).toBeVisible();

  const historyLink = page.getByRole('link', { name: 'History' });
  await expect(historyLink).toHaveAttribute(
    'href',
    new RegExp(`/doctor/history\\.php\\?patient_id=${patientId}&visit_id=${visitId}$`)
  );
  await historyLink.click();
  await expect(page.getByRole('heading', { name: 'Patient medical history' })).toBeVisible();
  await expect(page.getByText('Doctor audit privacy sentinel')).toBeVisible();

  await logout(page);
  await loginWithOtp(page, 'ui.admin@medishield.test');
  await page.goto('/admin/audit.php');

  const patientViewRows = page.getByRole('row')
    .filter({ hasText: 'PATIENT_VIEW' })
    .filter({ hasText: patientId });
  await expect(patientViewRows).toHaveCount(2);
  for (let index = 0; index < 2; index += 1) {
    const cells = patientViewRows.nth(index).getByRole('cell');
    await expect(cells.nth(1)).toHaveText(/^[1-9]\d*$/);
    await expect(cells.nth(2)).toHaveText('doctor');
    await expect(cells.nth(3)).toHaveText('PATIENT_VIEW');
    await expect(cells.nth(4)).toHaveText('doctor');
    await expect(cells.nth(5)).toHaveText('SUCCESS');
    await expect(cells.nth(6)).toHaveText('NORMAL');
    await expect(cells.nth(7)).toHaveText(patientId);
    await expect(cells.nth(8)).toHaveText('—');
  }
  await expect(page.getByText('Doctor audit privacy sentinel')).toHaveCount(0);
  await expect(page.getByText('Doctor audit treatment sentinel')).toHaveCount(0);
});
