const { test, expect } = require('@playwright/test');
const { loginWithOtp } = require('./helpers');

test.describe.configure({ mode: 'serial' });

async function registerPatient(page, fullName) {
  await page.goto('/register_patient.php');
  const patientNumber = await page.getByLabel('Patient number').inputValue();
  await page.getByLabel('Full name').fill(fullName);
  await page.getByLabel('Date of birth').fill('1990-01-01');
  await page.getByLabel('Gender').selectOption('female');
  await page.getByLabel('Phone').fill('0712345678');
  await page.getByLabel('Emergency contact').fill('Security Test +254711345678');
  await page.getByRole('button', { name: 'Register patient' }).click();
  return patientNumber;
}

test('blocks role and object-reference attacks without disclosing patient data', async ({ page }) => {
  const patientName = 'IDOR Protected Patient';
  const patientPhone = '0712345678';

  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  const patientNumber = await registerPatient(page, patientName);

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
  await loginWithOtp(page, 'ui.receptionist@medishield.test');

  const response = await page.request.post('/register_patient.php', {
    form: {
      patient_number: 'MSH-CCCCCCCCCCCCCCCC',
      full_name: 'CSRF Rejected Patient',
      date_of_birth: '1990-01-01',
      gender: 'female',
      phone: '0712345678',
      emergency_contact: 'Security Test +254711345678'
    }
  });

  expect(response.status()).toBe(200);
  await expect(response.text()).resolves.toContain('Your session has expired. Please try again.');

  await page.goto('/patients.php?q=CSRF%20Rejected%20Patient');
  await expect(page.getByText('No matching patients found.')).toBeVisible();
});

test('rejects a matching normalized emergency-contact number without creating a patient', async ({ page }) => {
  const patientName = 'Duplicate Emergency Contact Patient';

  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await page.goto('/register_patient.php');
  await page.getByLabel('Full name').fill(patientName);
  await page.getByLabel('Date of birth').fill('1990-01-01');
  await page.getByLabel('Gender').selectOption('female');
  await page.getByLabel('Phone').fill('+254712345678');
  await page.getByLabel('Emergency contact').fill('Emergency contact: 0712345678.');
  await page.getByRole('button', { name: 'Register patient' }).click();

  await expect(
    page.getByText('Patient phone and emergency contact number must be different.')
  ).toBeVisible();
  await page.goto(`/patients.php?q=${encodeURIComponent(patientName)}`);
  await expect(page.getByText('No matching patients found.')).toBeVisible();
});

test('renders stored hostile input as text rather than executable markup', async ({ page }) => {
  const payload = '<img src=x data-xss-probe="stored">';

  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  const patientNumber = await registerPatient(page, payload);

  await expect(page.locator('main .ms-muted').first()).toContainText(payload);
  await expect(page.locator('img[data-xss-probe="stored"]')).toHaveCount(0);

  await page.goto(`/patients.php?q=${encodeURIComponent(patientNumber)}`);
  await expect(page.locator('td').filter({ hasText: payload })).toHaveText(payload);
  await expect(page.locator('img[data-xss-probe="stored"]')).toHaveCount(0);
});

test('locks the displayed number and ignores a tampered patient number on registration', async ({ page }) => {
  const tamperedPatientNumber = 'MSH-FFFFFFFFFFFFFFFF';

  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await page.goto('/register_patient.php');

  const patientNumberInput = page.getByLabel('Patient number');
  const displayedPatientNumber = await patientNumberInput.inputValue();
  await expect(patientNumberInput).toHaveAttribute('readonly', '');
  await expect(displayedPatientNumber).toMatch(/^MSH-[A-F0-9]{16}$/);

  await patientNumberInput.evaluate((input, value) => {
    input.removeAttribute('readonly');
    input.setAttribute('name', 'patient_number');
    input.value = value;
  }, tamperedPatientNumber);
  await page.getByLabel('Full name').fill('Tamper Resistant Patient');
  await page.getByLabel('Date of birth').fill('1990-01-01');
  await page.getByLabel('Gender').selectOption('female');
  await page.getByLabel('Phone').fill('0712345678');
  await page.getByLabel('Emergency contact').fill('Security Test +254711345678');
  await page.getByRole('button', { name: 'Register patient' }).click();

  await expect(page.getByRole('heading', { name: 'Patient arrival' })).toBeVisible();
  await expect(page.locator('main .ms-muted').first()).toContainText(displayedPatientNumber);
  await expect(page.getByText(tamperedPatientNumber)).toHaveCount(0);
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
