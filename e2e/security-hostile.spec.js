const { test, expect } = require('@playwright/test');
const { loginWithOtp } = require('./helpers');

test.describe.configure({ mode: 'serial' });

async function registerPatient(page, patientNumber, fullName) {
  await page.goto('/register_patient.php');
  await page.getByLabel('Patient number').fill(patientNumber);
  await page.getByLabel('Full name').fill(fullName);
  await page.getByLabel('Date of birth').fill('1990-01-01');
  await page.getByLabel('Gender').selectOption('female');
  await page.getByLabel('Phone').fill('0712345678');
  await page.getByLabel('Emergency contact').fill('Security Test +254712345678');
  await page.getByRole('button', { name: 'Register patient' }).click();
}

test('blocks role and object-reference attacks without disclosing patient data', async ({ page }) => {
  const patientNumber = `IDOR-${Date.now()}`;
  const patientName = 'IDOR Protected Patient';
  const patientPhone = '0712345678';

  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await registerPatient(page, patientNumber, patientName);

  const patientId = new URL(page.url()).searchParams.get('patient_id');
  expect(patientId).not.toBeNull();

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.nurse@medishield.test');

  await page.goto(`/patient_profile.php?patient_id=${patientId}`);
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible();
  await expect(page.getByText(patientName)).not.toBeVisible();
  await expect(page.getByText(patientNumber)).not.toBeVisible();
  await expect(page.getByText(patientPhone)).not.toBeVisible();

  await page.goto('/admin/audit.php');
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible();
  await expect(page.getByText('Audit logs')).not.toBeVisible();
});

test('rejects a forged CSRF form POST without creating a patient', async ({ page }) => {
  const patientNumber = `CSRF-${Date.now()}`;

  await loginWithOtp(page, 'ui.receptionist@medishield.test');

  const response = await page.request.post('/register_patient.php', {
    form: {
      patient_number: patientNumber,
      full_name: 'CSRF Rejected Patient',
      date_of_birth: '1990-01-01',
      gender: 'female',
      phone: '0712345678',
      emergency_contact: 'Security Test +254712345678'
    }
  });

  expect(response.status()).toBe(200);
  await expect(response.text()).resolves.toContain('Your session has expired. Please try again.');

  await page.goto(`/patients.php?q=${encodeURIComponent(patientNumber)}`);
  await expect(page.getByText('No matching patients found.')).toBeVisible();
});

test('renders stored hostile input as text rather than executable markup', async ({ page }) => {
  const patientNumber = `XSS-${Date.now()}`;
  const payload = '<img src=x data-xss-probe="stored">';

  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await registerPatient(page, patientNumber, payload);

  await expect(page.locator('main .ms-muted').first()).toContainText(payload);
  await expect(page.locator('img[data-xss-probe="stored"]')).toHaveCount(0);

  await page.goto(`/patients.php?q=${encodeURIComponent(patientNumber)}`);
  await expect(page.locator('td').filter({ hasText: payload })).toHaveText(payload);
  await expect(page.locator('img[data-xss-probe="stored"]')).toHaveCount(0);
});

test('sends security headers and gives generic invalid-login errors', async ({ page }) => {
  const response = await page.request.get('/login.php');

  expect(response.headers()['x-frame-options']).toBe('DENY');
  expect(response.headers()['x-content-type-options']).toBe('nosniff');
  expect(response.headers()['referrer-policy']).toBe('no-referrer-when-downgrade');
  expect(response.headers()['content-security-policy']).toContain("default-src 'self'");
  expect(response.headers()['permissions-policy']).toContain('geolocation=()');
  expect(response.headers()['x-powered-by']).toBeUndefined();

  for (const email of ['ui.receptionist@medishield.test', 'unknown@medishield.test']) {
    await page.goto('/login.php');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill('Incorrect!2026');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByText('Invalid email or password.')).toBeVisible();
    await expect(page.getByText(/account .* does not exist/i)).toHaveCount(0);
  }
});
