const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');
const {
  auditEventsAfter,
  latestAuditId,
  loginWithOtp,
  logout,
  readNewMail
} = require('./helpers');

const root = path.resolve(__dirname, '..');
const mailDir = process.env.MEDISHIELD_MAIL_DUMP_DIR
  || path.join(root, 'test-results', 'mail');
const activationEmail = 'account.activation@medishield.test';
const activationPassword = 'Activated!Pass2026';
const resetPassword = 'Replacement!Pass2026';

test.describe.configure({ mode: 'serial' });

function activationToken(message) {
  const match = message.match(/activate\.php\?token=([a-f0-9]+)/i);
  expect(match, 'activation email contains a usable link').not.toBeNull();
  return match[1];
}

async function createPendingPatientUser(page) {
  const messagesBefore = fs.readdirSync(mailDir).length;

  await page.goto('/admin/create_user.php');
  await page.getByLabel('Full name').fill('Account Coverage Patient');
  await page.getByLabel('Email').fill(activationEmail);
  await page.getByLabel('Role').selectOption('patient');
  await page.getByRole('button', { name: 'Create user' }).click();
  await expect(page.getByText('User created. An activation link has been emailed so they can set their own password and activate the account.')).toBeVisible();

  return activationToken(await readNewMail(mailDir, messagesBefore));
}

test('administrator creates, activates, resets, and safely manages a user account', async ({ page }) => {
  const loginAuditStart = latestAuditId();
  await loginWithOtp(page, 'ui.admin@medishield.test');
  const loginEvents = auditEventsAfter(loginAuditStart);
  const loginActions = loginEvents.map((event) => event.action);
  expect(loginActions).toContain('OTP_SENT');
  expect(loginActions).toContain('OTP_VERIFIED');
  expect(loginActions).toContain('LOGIN_SUCCESS');
  expect(loginActions.indexOf('LOGIN_SUCCESS')).toBeGreaterThan(loginActions.indexOf('OTP_VERIFIED'));
  expect(loginEvents.find((event) => event.action === 'LOGIN_SUCCESS')).toMatchObject({
    user_role: 'admin',
    status: 'SUCCESS',
    attempted_identifier: null
  });
  await page.goto('/admin/audit.php');
  await expect(page.getByText('UNKNOWN', { exact: true })).toBeVisible();
  await expect(page.getByText(/Audit rollback status is UNKNOWN/)).toBeVisible();
  const token = await createPendingPatientUser(page);

  await logout(page);
  await page.goto(`/activate.php?token=${token}`);
  const activationPasswordInput = page.getByLabel('New password', { exact: true });
  const activationConfirmationInput = page.getByLabel('Confirm password');
  await expect(activationPasswordInput).toHaveAttribute('minlength', '12');
  await expect(activationConfirmationInput).toHaveAttribute('minlength', '12');
  await activationPasswordInput.fill('Weak');
  await activationConfirmationInput.fill('Different!Pass2026');
  await page.getByRole('button', { name: 'Activate account' }).click();
  await expect(page.getByText('The two passwords do not match.')).toBeVisible();

  await page.getByLabel('New password', { exact: true }).fill('weak');
  await page.getByLabel('Confirm password').fill('weak');
  await page.getByRole('button', { name: 'Activate account' }).click();
  await expect(page.getByText('Password must be at least 12 characters long.')).toBeVisible();

  await page.getByLabel('New password', { exact: true }).fill(activationPassword);
  await page.getByLabel('Confirm password').fill(activationPassword);
  const activationAuditStart = latestAuditId();
  await page.getByRole('button', { name: 'Activate account' }).click();
  await expect(page.getByText('Your account is now active. You can sign in with your new password.')).toBeVisible();
  const activationEvents = auditEventsAfter(activationAuditStart);
  expect(activationEvents).toHaveLength(1);
  expect(activationEvents[0]).toMatchObject({
    user_role: 'patient',
    action: 'ACCOUNT_ACTIVATED',
    status: 'SUCCESS',
    attempted_identifier: null
  });

  await loginWithOtp(page, activationEmail, activationPassword);
  await expect(page.getByRole('heading', { name: 'Patient dashboard' })).toBeVisible();
  await expect(page.getByText('No patient record is linked to your login yet. Please contact the administrator.')).toBeVisible();

  await logout(page);
  await loginWithOtp(page, 'ui.admin@medishield.test');
  await page.goto('/admin/users.php');

  const selfRow = page.getByRole('row').filter({ hasText: 'ui.admin@medishield.test' });
  await expect(selfRow.getByText('(you)')).toBeVisible();
  await expect(selfRow.getByRole('button', { name: /Deactivate|Activate/ })).toHaveCount(0);
  const csrf = await page.locator('input[type="hidden"]').first().evaluate((input) => ({
    name: input.name,
    value: input.value
  }));
  const selfId = (await selfRow.locator('td').first().textContent()).trim();
  const selfProtectionResponse = await page.evaluate(async ({ csrf, selfId }) => {
    const body = new URLSearchParams({
      [csrf.name]: csrf.value,
      user_id: selfId,
      status: 'inactive'
    });
    const response = await fetch('/admin/users.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });
    return response.text();
  }, { csrf, selfId });
  expect(selfProtectionResponse).toContain('You cannot change the status of your own account.');

  const accountRow = page.getByRole('row').filter({ hasText: activationEmail });
  await accountRow.getByRole('button', { name: 'Deactivate' }).click();
  await expect(accountRow.getByText('inactive')).toBeVisible();
  await accountRow.getByRole('button', { name: 'Activate' }).click();
  await expect(accountRow.getByText('active')).toBeVisible();

  const messagesBefore = fs.readdirSync(mailDir).length;
  await accountRow.getByRole('button', { name: 'Send password reset' }).click();
  await expect(page.getByText('Password reset link sent to the user.')).toBeVisible();
  const resetToken = activationToken(await readNewMail(mailDir, messagesBefore));

  await logout(page);
  await page.goto(`/activate.php?token=${resetToken}`);
  await page.getByLabel('New password', { exact: true }).fill(resetPassword);
  await page.getByLabel('Confirm password').fill(resetPassword);
  await page.getByRole('button', { name: 'Activate account' }).click();
  await expect(page.getByText('Your account is now active. You can sign in with your new password.')).toBeVisible();

  await loginWithOtp(page, activationEmail, resetPassword);
  await expect(page.getByRole('heading', { name: 'Patient dashboard' })).toBeVisible();
});

test('forces an initial password change and validates voluntary password changes', async ({ page }) => {
  const forcedPassword = 'Forced!Pass2026';
  const voluntaryPassword = 'Voluntary!Pass2026';

  await loginWithOtp(page, 'ui.forced-password-admin@medishield.test', 'UiTest!2026A');
  await expect(page.getByRole('heading', { name: 'Change your password' })).toBeVisible();
  await expect(page.getByText('For your security you must set a new password before continuing.')).toBeVisible();
  await expect(page.getByLabel('New password', { exact: true })).toHaveAttribute('minlength', '12');
  await expect(page.getByLabel('Confirm new password')).toHaveAttribute('minlength', '12');

  await page.getByLabel('Current password').fill('UiTest!2026A');
  await page.getByLabel('New password', { exact: true }).fill(forcedPassword);
  await page.getByLabel('Confirm new password').fill('Mismatch!Pass2026');
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByText('The new password and its confirmation do not match.')).toBeVisible();

  await page.getByLabel('Current password').fill('Incorrect!Pass2026');
  await page.getByLabel('New password', { exact: true }).fill(forcedPassword);
  await page.getByLabel('Confirm new password').fill(forcedPassword);
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByText('Your current password is incorrect.')).toBeVisible();

  await page.getByLabel('Current password').fill('UiTest!2026A');
  await page.getByLabel('New password', { exact: true }).fill(forcedPassword);
  await page.getByLabel('Confirm new password').fill(forcedPassword);
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await loginWithOtp(page, 'ui.forced-password-admin@medishield.test', forcedPassword);
  await expect(page.getByRole('heading', { name: 'Administrator dashboard' })).toBeVisible();

  await page.goto('/change_password.php');
  await page.getByLabel('Current password').fill(forcedPassword);
  await page.getByLabel('New password', { exact: true }).fill(forcedPassword);
  await page.getByLabel('Confirm new password').fill(forcedPassword);
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByText('The new password must be different from the current password.')).toBeVisible();

  await page.getByLabel('Current password').fill(forcedPassword);
  await page.getByLabel('New password', { exact: true }).fill('short');
  await page.getByLabel('Confirm new password').fill('short');
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByText('Password must be at least 12 characters long.')).toBeVisible();

  await page.getByLabel('Current password').fill(forcedPassword);
  await page.getByLabel('New password', { exact: true }).fill(voluntaryPassword);
  await page.getByLabel('Confirm new password').fill(voluntaryPassword);
  await page.getByRole('button', { name: 'Update password' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await loginWithOtp(page, 'ui.forced-password-admin@medishield.test', voluntaryPassword);
  await expect(page.getByRole('heading', { name: 'Administrator dashboard' })).toBeVisible();
});

test('patient self-service shows only the linked patient record and denies another patient', async ({ page }) => {
  execFileSync('php', [path.join(root, 'scripts', 'seed-ui-dashboard-data.php')], {
    cwd: root,
    stdio: 'inherit',
    env: {
      ...process.env,
      MEDISHIELD_DB_NAME: process.env.MEDISHIELD_DB_NAME || 'medishield_ui_test',
      MEDISHIELD_DASHBOARD_PATIENT_ONLY: '1'
    }
  });

  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await page.goto('/register_patient.php');
  await page.getByLabel('Full name').fill('Patient Ownership Denial Target');
  await page.getByLabel('Date of birth').fill('1991-02-03');
  await page.getByLabel('Gender').selectOption('female');
  await page.getByLabel('Phone').fill('0712345678');
  await page.getByLabel('Emergency contact').fill('Ownership Contact 0723456789');
  await page.getByRole('button', { name: 'Register patient' }).click();
  const otherPatientId = new URL(page.url()).searchParams.get('patient_id');
  expect(otherPatientId).not.toBeNull();

  await logout(page);
  await loginWithOtp(page, 'ui.patient@medishield.test');
  await expect(page.getByRole('heading', { name: 'Patient dashboard' })).toBeVisible();
  await expect(page.getByTestId('patient-vitals-count')).toHaveText('1');
  await expect(page.getByTestId('patient-records-count')).toHaveText('1');
  await expect(page.getByTestId('patient-lab-results-count')).toHaveText('1');
  await expect(page.getByTestId('patient-prescriptions-count')).toHaveText('1');

  await page.getByRole('link', { name: 'Profile' }).click();
  await expect(page.getByRole('heading', { name: 'UI Dashboard Patient' })).toBeVisible();
  await page.goto('/patient/records.php');
  await expect(page.getByText('Routine dashboard test observation')).toBeVisible();
  await expect(page.getByText('Dashboard follow-up')).toBeVisible();
  await page.goto('/patient/lab_results.php');
  await expect(page.getByText('5.2 mmol/L')).toBeVisible();
  await page.goto('/patient/prescriptions.php');
  await expect(page.getByText('Paracetamol 500 mg')).toBeVisible();

  await page.goto(`/patient_profile.php?patient_id=${otherPatientId}`);
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible();
  await expect(page.getByText('Patient Ownership Denial Target')).not.toBeVisible();
  await expect(page.getByText('UI Dashboard Patient')).not.toBeVisible();
});
