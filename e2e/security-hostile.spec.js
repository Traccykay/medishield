const { test, expect } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const { loginWithOtp } = require('./helpers');

test.describe.configure({ mode: 'serial' });

test('denies direct access to include-only billing partials without leaking errors', async ({ page }) => {
  for (const partialPath of [
    '/partials/bill_charges.php',
    '/Partials/bill_charges.php',
    '/PARTIALS/bill_charges.php'
  ]) {
    const response = await page.request.get(partialPath);
    const body = await response.text();

    expect([403, 404]).toContain(response.status());
    expect(body).not.toContain('description_snapshot');
    expect(body).not.toContain('Stack trace');
    expect(body).not.toContain('C:\\');
  }
});

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

test('revoked doctor assignment immediately blocks reads, IDOR, and mutation', async ({ page }) => {
  const patientName = 'Revocation Protected Patient';
  const authorizedDiagnosis = 'Authorized revocation baseline';
  const forgedDiagnosis = 'Forged after revocation';
  const authorizedDoctorEmail = 'ui.other-doctor@medishield.test';
  const wrongDoctorEmail = 'ui.doctor@medishield.test';

  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await registerPatient(page, patientName);
  const patientId = new URL(page.url()).searchParams.get('patient_id');
  expect(patientId).not.toBeNull();
  await page.getByLabel('Payment method').selectOption('cash');
  await page.getByRole('button', { name: 'Add to triage queue' }).click();

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  await page.goto('/nurse/triage.php');
  const triageRow = page.getByRole('row').filter({ hasText: patientName });
  await triageRow.getByRole('button', { name: 'Start triage' }).click();
  await page.getByLabel('Temperature C').fill('37.4');
  await page.getByLabel('Systolic mmHg').fill('121');
  await page.getByLabel('Diastolic mmHg').fill('81');
  await page.getByLabel('Pulse bpm').fill('73');
  await page.getByLabel('Weight kg').fill('66');
  await page.getByLabel('Symptoms / observations').fill('Revocation protected symptoms');
  await page.getByRole('button', { name: 'Save vitals' }).click();
  await page.goto('/nurse/dashboard.php');
  const nurseRow = page.getByRole('row').filter({ hasText: patientName });
  await nurseRow.getByRole('link', { name: 'Assign doctor' }).click();
  await page.getByLabel('Doctor').selectOption({
    label: 'UI Other Doctor (ui.other-doctor@medishield.test)'
  });
  await page.getByRole('button', { name: 'Assign doctor' }).click();

  await page.goto('/logout.php');
  await loginWithOtp(page, authorizedDoctorEmail);
  const consultationRow = page.getByRole('row').filter({ hasText: patientName });
  const consultationHref = await consultationRow.getByRole('link', { name: 'Open' }).getAttribute('href');
  const consultationUrl = new URL(consultationHref, page.url());
  const visitId = consultationUrl.searchParams.get('visit_id');
  expect(visitId).not.toBeNull();
  await consultationRow.getByRole('link', { name: 'Open' }).click();
  await page.getByRole('link', { name: 'Add diagnosis' }).click();
  await page.getByLabel('Diagnosis').fill(authorizedDiagnosis);
  await page.getByRole('button', { name: 'Save consultation and selected orders' }).click();
  await expect(page.getByText(authorizedDiagnosis)).toBeVisible();

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.admin@medishield.test');
  await page.goto(`/admin/assign_patient.php?patient_id=${patientId}`);
  const doctorAssignment = page.getByRole('row').filter({ hasText: authorizedDoctorEmail });
  await doctorAssignment.getByRole('button', { name: 'Unassign' }).click();
  await expect(page.getByText('Assignment removed.')).toBeVisible();

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  const recoveredNurseRow = page.getByRole('row')
    .filter({ hasText: patientName })
    .filter({ has: page.getByRole('link', { name: 'Assign doctor' }) });
  await expect(recoveredNurseRow).toBeVisible();
  await recoveredNurseRow.getByRole('link', { name: 'Assign doctor' }).click();
  await expect(page.getByLabel('Doctor').locator(`option:has-text("${authorizedDoctorEmail}")`)).toHaveCount(1);

  await page.goto('/logout.php');
  await loginWithOtp(page, authorizedDoctorEmail);
  await expect(page.getByText(patientName)).toHaveCount(0);
  for (const url of [
    `/doctor/view_patient.php?patient_id=${patientId}&visit_id=${visitId}`,
    `/doctor/history.php?patient_id=${patientId}&visit_id=${visitId}`,
    `/patient_profile.php?patient_id=${patientId}&visit_id=${visitId}`
  ]) {
    await page.goto(url);
    await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible();
    await expect(page.getByText(patientName)).toHaveCount(0);
    await expect(page.getByText('Revocation protected symptoms')).toHaveCount(0);
    await expect(page.getByText(authorizedDiagnosis)).toHaveCount(0);
  }

  await page.goto('/change_password.php');
  const csrfToken = await page.locator('input[name="csrf_token"]').inputValue();
  const deniedMutation = await page.request.post('/doctor/add_diagnosis.php', {
    form: {
      csrf_token: csrfToken,
      patient_id: patientId,
      visit_id: visitId,
      diagnosis: forgedDiagnosis
    }
  });
  expect(deniedMutation.status()).toBe(403);

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.admin@medishield.test');
  await page.goto('/admin/audit.php');
  const denialRow = page.getByRole('row')
    .filter({ hasText: 'UNAUTHORIZED_ACCESS' })
    .filter({ hasText: patientId })
    .first();
  await expect(denialRow).toContainText('doctor');
  await expect(denialRow).toContainText('BLOCKED');
  await expect(denialRow).toContainText('HIGH_RISK');

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  const rerouteRow = page.getByRole('row')
    .filter({ hasText: patientName })
    .filter({ has: page.getByRole('link', { name: 'Assign doctor' }) });
  await rerouteRow.getByRole('link', { name: 'Assign doctor' }).click();
  await page.getByLabel('Doctor').selectOption({
    label: 'UI Other Doctor (ui.other-doctor@medishield.test)'
  });
  await page.getByRole('button', { name: 'Assign doctor' }).click();

  await page.goto('/logout.php');
  await loginWithOtp(page, authorizedDoctorEmail);
  await page.goto(`/doctor/view_patient.php?patient_id=${patientId}&visit_id=${visitId}`);
  await expect(page.getByText(authorizedDiagnosis)).toBeVisible();
  await expect(page.getByText(forgedDiagnosis)).toHaveCount(0);

  await page.goto('/logout.php');
  await loginWithOtp(page, wrongDoctorEmail);
  await page.goto(`/doctor/view_patient.php?patient_id=${patientId}&visit_id=${visitId}`);
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible();
  await expect(page.getByText(patientName)).toHaveCount(0);
  await expect(page.getByText(authorizedDiagnosis)).toHaveCount(0);
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
  expect(response.headers()['content-security-policy']).toContain("base-uri 'self'");
  expect(response.headers()['content-security-policy']).not.toContain("'unsafe-inline'");
  expect(response.headers()['permissions-policy']).toContain('geolocation=()');
  expect(response.headers()['cross-origin-embedder-policy']).toBe('require-corp');
  expect(response.headers()['cross-origin-opener-policy']).toBe('same-origin');
  expect(response.headers()['cross-origin-resource-policy']).toBe('same-origin');
  expect(response.headers()['x-powered-by']).toBeUndefined();

  const stylesheet = await page.request.get('/assets/css/style.css');
  expect(stylesheet.headers()['x-content-type-options']).toBe('nosniff');
  expect(stylesheet.headers()['cross-origin-resource-policy']).toBe('same-origin');

  for (const email of ['ui.receptionist@medishield.test', 'unknown@medishield.test']) {
    await page.goto('/login.php');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill('Incorrect!2026');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByText('Invalid email or password.')).toBeVisible();
    await expect(page.getByText(/account .* does not exist/i)).toHaveCount(0);
  }
});

test('revokes an outstanding reset link when an administrator deactivates the account', async ({ page }) => {
  const mailDir = path.join(__dirname, '..', 'test-results', 'mail');
  const messagesBefore = fs.readdirSync(mailDir).length;

  await page.goto('/forgot_password.php');
  await page.getByLabel('Email').fill('ui.doctor@medishield.test');
  await page.getByRole('button', { name: 'Send reset link' }).click();
  await expect(page.getByText('If that email belongs to an active account, a password reset link has been sent.')).toBeVisible();

  const resetMessage = fs.readdirSync(mailDir)
    .map((file) => ({ file, mtime: fs.statSync(path.join(mailDir, file)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)
    .slice(0, fs.readdirSync(mailDir).length - messagesBefore)[0];
  const resetToken = fs.readFileSync(path.join(mailDir, resetMessage.file), 'utf8')
    .match(/activate\.php\?token=([a-f0-9]+)/i)[1];

  await loginWithOtp(page, 'ui.admin@medishield.test');
  await page.goto('/admin/users.php');
  const doctorRow = page.getByRole('row').filter({ hasText: 'ui.doctor@medishield.test' });
  await doctorRow.getByRole('button', { name: 'Deactivate' }).click();
  await expect(doctorRow.getByText('inactive')).toBeVisible();

  await page.goto('/logout.php');
  await page.goto(`/activate.php?token=${resetToken}`);
  await expect(page.getByText('This activation link is invalid or has already been used.')).toBeVisible();
  await expect(page.getByLabel('New password')).toHaveCount(0);
});

test('throttles a password-reset storm without sending more email after the block', async ({ page }) => {
  const mailDir = path.join(__dirname, '..', 'test-results', 'mail');
  let blocked = false;

  // The browser must obtain a fresh CSRF token for every real form submission.
  // Stop as soon as the server-side, IP-scoped limit is reached so the scenario
  // remains valid whether an earlier test used the same disposable address.
  for (let attempt = 0; attempt < 12; attempt += 1) {
    await page.goto('/forgot_password.php');
    await page.getByLabel('Email').fill(`throttle-${attempt}@medishield.test`);
    await page.getByRole('button', { name: 'Send reset link' }).click();
    if (await page.getByText('Too many password-reset requests. Please try again later.').isVisible()) {
      blocked = true;
      break;
    }
  }

  expect(blocked).toBe(true);
  const mailCountAtBlock = fs.readdirSync(mailDir).length;

  await page.goto('/forgot_password.php');
  await page.getByLabel('Email').fill('ui.doctor@medishield.test');
  await page.getByRole('button', { name: 'Send reset link' }).click();

  await expect(page.getByText('Too many password-reset requests. Please try again later.')).toBeVisible();
  expect(fs.readdirSync(mailDir).length).toBe(mailCountAtBlock);
});
