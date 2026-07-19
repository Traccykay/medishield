const { execFileSync } = require('node:child_process');
const path = require('node:path');
const { test, expect } = require('@playwright/test');
const { loginWithOtp } = require('./helpers');

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

test.afterAll(() => {
  resetUiDatabase();
});

test('role dashboards retain useful empty states before work begins', async ({ page }) => {
  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await expect(page.getByTestId('reception-triage-count')).toHaveText('0');
  await expect(page.getByText('No patients waiting.')).toBeVisible();

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  await expect(page.getByTestId('nurse-triage-count')).toHaveText('0');
  await expect(page.getByTestId('nurse-vitals-count')).toHaveText('0');
  await expect(page.getByText('No assigned patients yet.')).toBeVisible();

  await page.goto('/logout.php');
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

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  await expect(page.getByTestId('nurse-triage-count')).toHaveText('1');
  await expect(page.getByTestId('nurse-vitals-count')).toHaveText('1');

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.doctor@medishield.test');
  await expect(page.getByTestId('doctor-consultations-count')).toHaveText('1');
  await expect(page.getByTestId('doctor-pending-labs-count')).toHaveText('1');
  await expect(page.getByTestId('doctor-pending-prescriptions-count')).toHaveText('1');

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.lab@medishield.test');
  await expect(page.getByTestId('lab-pending-count')).toHaveText('1');
  await expect(page.getByTestId('lab-completed-count')).toHaveText('1');

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.pharmacist@medishield.test');
  await expect(page.getByTestId('pharmacy-pending-count')).toHaveText('1');
  await expect(page.getByTestId('pharmacy-dispensed-count')).toHaveText('1');
  await expect(page.getByTestId('pharmacy-pending-total')).toHaveText('KES 150');

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.patient@medishield.test');
  await expect(page.getByTestId('patient-vitals-count')).toHaveText('1');
  await expect(page.getByTestId('patient-records-count')).toHaveText('1');
  await expect(page.getByTestId('patient-lab-results-count')).toHaveText('1');
  await expect(page.getByTestId('patient-prescriptions-count')).toHaveText('1');

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.admin@medishield.test');
  await expect(page.getByTestId('admin-active-users-count')).toHaveText(/^[1-9]\d*$/);
  await expect(page.getByTestId('admin-recent-audit-count')).not.toHaveText('0');
});
