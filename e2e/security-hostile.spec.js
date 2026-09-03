const { test, expect } = require('@playwright/test');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { loginWithOtp, logout, readNewMail } = require('./helpers');

test.describe.configure({ mode: 'serial' });

function mysql(sql) {
  return execFileSync('mysql.exe', [
    '--host=127.0.0.1',
    '--user=root',
    '--database=medishield_ui_test',
    '--batch',
    '--skip-column-names',
    '--raw',
    `--execute=${sql}`
  ], { encoding: 'utf8' }).trim();
}

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

  await logout(page);
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

test('records missing-anchor verification as normal without inflating dashboard security counters', async ({ page }) => {
  await loginWithOtp(page, 'ui.admin@medishield.test');
  const [failedBefore, anomaliesBefore] = mysql(
    "SELECT SUM(status = 'FAILED'), SUM(anomaly_flag <> 'NORMAL') FROM audit_logs"
  ).split('\t').map(Number);
  const auditStart = Number(mysql('SELECT COALESCE(MAX(log_id), 0) FROM audit_logs'));

  await page.goto('/admin/audit.php');
  await expect(page.locator('.ms-stat-num').filter({ hasText: /^UNKNOWN$/ })).toBeVisible();
  const [status, anomaly] = mysql(
    `SELECT status, anomaly_flag
       FROM audit_logs
      WHERE action = 'INTEGRITY_VERIFIED' AND log_id > ${auditStart}
      ORDER BY log_id ASC
      LIMIT 1`
  ).split('\t');

  expect(status).toBe('SUCCESS');
  expect(anomaly).toBe('NORMAL');

  const [failedAfter, anomaliesAfter] = mysql(
    "SELECT SUM(status = 'FAILED'), SUM(anomaly_flag <> 'NORMAL') FROM audit_logs"
  ).split('\t').map(Number);
  expect(failedAfter).toBe(failedBefore);
  expect(anomaliesAfter).toBe(anomaliesBefore);

  await page.goto('/admin/dashboard.php');
  const [recentFailed, recentAnomalies] = mysql(
    `SELECT SUM(status = 'FAILED'), SUM(anomaly_flag <> 'NORMAL')
       FROM (
         SELECT status, anomaly_flag
           FROM audit_logs
          ORDER BY seq DESC
          LIMIT 25
       ) AS recent_audit`
  ).split('\t').map(Number);
  await expect(page.getByTestId('admin-failed-events-count')).toHaveText(String(recentFailed));
  await expect(page.getByTestId('admin-anomaly-count')).toHaveText(String(recentAnomalies));
});

test('does not recursively append integrity evidence for an unanchored suffix', async ({ page }) => {
  await loginWithOtp(page, 'ui.admin@medishield.test');
  const root = path.resolve(__dirname, '..');
  execFileSync('php', [path.join(root, 'scripts', 'anchor-audit-chain.php')], {
    cwd: root,
    stdio: 'inherit',
    env: {
      ...process.env,
      MEDISHIELD_AUDIT_DB_NAME: 'medishield_ui_test',
      MEDISHIELD_AUDIT_ANCHOR_PATH: path.join(root, 'test-results', 'audit-anchor.jsonl')
    }
  });
  const beforePass = Number(mysql(
    "SELECT COUNT(*) FROM audit_logs WHERE action = 'INTEGRITY_VERIFIED'"
  ));

  await page.goto('/admin/audit.php');
  await expect(page.locator('.ms-stat-num').filter({ hasText: /^PASS$/ })).toBeVisible();
  const afterPass = Number(mysql(
    "SELECT COUNT(*) FROM audit_logs WHERE action = 'INTEGRITY_VERIFIED'"
  ));
  expect(afterPass).toBe(beforePass + 1);

  await page.reload();
  await expect(page.locator('.ms-stat-num').filter({ hasText: /^UNKNOWN$/ })).toBeVisible();
  const afterSuffix = Number(mysql(
    "SELECT COUNT(*) FROM audit_logs WHERE action = 'INTEGRITY_VERIFIED'"
  ));
  expect(afterSuffix).toBe(afterPass);
});

test('quarantines recent audit rows when local integrity verification fails', async ({ page }) => {
  await loginWithOtp(page, 'ui.admin@medishield.test');
  const [logId, originalActionHex] = mysql(
    'SELECT log_id, HEX(action) FROM audit_logs ORDER BY seq ASC LIMIT 1'
  ).split('\t');
  expect(logId).toMatch(/^[1-9]\d*$/);
  expect(originalActionHex).toMatch(/^[0-9A-F]+$/);

  mysql(`UPDATE audit_logs SET action = 'FORGED_UI_AUDIT_ROW' WHERE log_id = ${logId}`);
  try {
    await page.goto('/admin/audit.php');
    await expect(page.locator('.ms-stat-num').filter({ hasText: /^FAIL$/ })).toBeVisible();
    await expect(page.getByText(
      'Recent audit rows are quarantined from display because local chain integrity was not verified.'
    )).toBeVisible();
    await expect(page.getByText('FORGED_UI_AUDIT_ROW')).toHaveCount(0);
  } finally {
    mysql(
      `UPDATE audit_logs SET action = UNHEX('${originalActionHex}') WHERE log_id = ${logId}`
    );
  }

  await page.reload();
  await expect(page.getByText(
    'Recent audit rows are quarantined from display because local chain integrity was not verified.'
  )).toHaveCount(0);
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

  await logout(page);
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

  await logout(page);
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

  await logout(page);
  await loginWithOtp(page, 'ui.admin@medishield.test');
  await page.goto(`/admin/assign_patient.php?patient_id=${patientId}`);
  const doctorAssignment = page.getByRole('row').filter({ hasText: authorizedDoctorEmail });
  await doctorAssignment.getByRole('button', { name: 'Unassign' }).click();
  await expect(page.getByText('Assignment removed.')).toBeVisible();

  await logout(page);
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  const recoveredNurseRow = page.getByRole('row')
    .filter({ hasText: patientName })
    .filter({ has: page.getByRole('link', { name: 'Assign doctor' }) });
  await expect(recoveredNurseRow).toBeVisible();
  await recoveredNurseRow.getByRole('link', { name: 'Assign doctor' }).click();
  await expect(page.getByLabel('Doctor').locator(`option:has-text("${authorizedDoctorEmail}")`)).toHaveCount(1);

  await logout(page);
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
  const csrfToken = await page.locator('input[name="csrf_token"]').first().inputValue();
  const deniedMutation = await page.request.post('/doctor/add_diagnosis.php', {
    form: {
      csrf_token: csrfToken,
      patient_id: patientId,
      visit_id: visitId,
      diagnosis: forgedDiagnosis
    }
  });
  expect(deniedMutation.status()).toBe(403);

  await logout(page);
  await loginWithOtp(page, 'ui.admin@medishield.test');
  await page.goto('/admin/audit.php');
  const denialRow = page.getByRole('row')
    .filter({ hasText: 'UNAUTHORIZED_ACCESS' })
    .filter({ hasText: patientId })
    .first();
  await expect(denialRow).toContainText('doctor');
  await expect(denialRow).toContainText('BLOCKED');
  await expect(denialRow).toContainText('HIGH_RISK');

  await logout(page);
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  const rerouteRow = page.getByRole('row')
    .filter({ hasText: patientName })
    .filter({ has: page.getByRole('link', { name: 'Assign doctor' }) });
  await rerouteRow.getByRole('link', { name: 'Assign doctor' }).click();
  await page.getByLabel('Doctor').selectOption({
    label: 'UI Other Doctor (ui.other-doctor@medishield.test)'
  });
  await page.getByRole('button', { name: 'Assign doctor' }).click();

  await logout(page);
  await loginWithOtp(page, authorizedDoctorEmail);
  await page.goto(`/doctor/view_patient.php?patient_id=${patientId}&visit_id=${visitId}`);
  await expect(page.getByText(authorizedDiagnosis)).toBeVisible();
  await expect(page.getByText(forgedDiagnosis)).toHaveCount(0);

  await logout(page);
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

  expect(response.status()).toBe(403);
  await expect(response.text()).resolves.toBe('Request could not be processed.');

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
  expect(response.headers()['referrer-policy']).toBe('no-referrer');
  expect(response.headers()['content-security-policy']).toContain("default-src 'self'");
  expect(response.headers()['content-security-policy']).toContain("base-uri 'self'");
  expect(response.headers()['content-security-policy']).not.toContain("'unsafe-inline'");
  expect(response.headers()['permissions-policy']).toContain('geolocation=()');
  expect(response.headers()['cross-origin-embedder-policy']).toBe('require-corp');
  expect(response.headers()['cross-origin-opener-policy']).toBe('same-origin');
  expect(response.headers()['cross-origin-resource-policy']).toBe('same-origin');
  expect(response.headers()['x-powered-by']).toBeUndefined();
  expect(response.headers()['cache-control']).toContain('no-store');
  expect(response.headers()['cache-control']).toContain('private');
  expect(response.headersArray().filter(
    ({ name }) => name.toLowerCase() === 'referrer-policy'
  )).toHaveLength(1);

  const stylesheet = await page.request.get('/assets/css/style.css');
  expect(stylesheet.headers()['content-type']).toBe('text/css; charset=utf-8');
  expect(stylesheet.headers()['x-content-type-options']).toBe('nosniff');
  expect(stylesheet.headers()['cross-origin-resource-policy']).toBe('same-origin');
  expect(stylesheet.headers()['cache-control']).toContain('public');
  expect(stylesheet.headers()['cache-control']).not.toContain('no-store');
  await page.goto('/login.php');
  expect(await page.locator('body').evaluate(
    (body) => getComputedStyle(body).marginTop
  )).toBe('0px');
  expect(await page.locator('.ms-nav').evaluate(
    (nav) => getComputedStyle(nav).backgroundColor
  )).toBe('rgb(11, 110, 153)');

  for (const target of [
    '/README.md',
    '/.htaccess',
    '/router.php',
    '/assets/README.md',
    '/assets/css/style.css.map',
    '/login.php.bak',
    '/manifest.json',
    '/src/Auth/AuthService.php',
    '/config/config.php',
    '/assets/%2e%2e/router.php'
  ]) {
    const denied = await page.request.get(target, { maxRedirects: 0 });
    expect(denied.status(), target).toBe(403);
    await expect(denied.text()).resolves.toBe('Forbidden.\n');
    expect(denied.headers()['referrer-policy'], target).toBe('no-referrer');
    expect(denied.headers()['x-content-type-options'], target).toBe('nosniff');
  }

  for (const target of ['/not-a-route.php', '/login', '/assets/css/']) {
    const missing = await page.request.get(target, { maxRedirects: 0 });
    expect(missing.status(), target).toBe(404);
    await expect(missing.text()).resolves.toBe('Not found.\n');
    expect(missing.headers()['referrer-policy'], target).toBe('no-referrer');
  }

  const attempts = [
    ['ui.receptionist@medishield.test', 'Incorrect!2026'],
    ['ui.inactive-probe@medishield.test', 'UiTest!2026A'],
    ['unknown@medishield.test', 'Incorrect!2026'],
  ];
  for (let attempt = 0; attempt < 5; attempt += 1) {
    attempts.push(['ui.login-probe@medishield.test', 'Incorrect!2026']);
  }
  attempts.push(['ui.login-probe@medishield.test', 'UiTest!2026A']);

  for (const [email, password] of attempts) {
    await page.goto('/login.php');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByText('Invalid email or password.')).toBeVisible();
    await expect(page.getByText(/temporarily locked/i)).toHaveCount(0);
    await expect(page.getByText(/account .* does not exist/i)).toHaveCount(0);
  }
});

test('array-shaped read parameters fail closed without PHP diagnostics', async ({ page }) => {
  await loginWithOtp(page, 'ui.nurse@medishield.test');

  const vitals = await page.request.get('/nurse/view_vitals.php?patient_id[]=1', {
    maxRedirects: 0
  });
  expect(vitals.status()).toBe(403);
  expect(vitals.headers().location).toBeUndefined();
  await expect(vitals.text()).resolves.toContain('Access denied');

  const patients = await page.request.get('/patients.php?q[]=patient');
  expect(patients.status()).toBe(200);
  await expect(patients.text()).resolves.not.toContain('TypeError');

  await page.context().clearCookies();
  await page.goto('/login.php');
  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  const reception = await page.request.get('/reception/dashboard.php?q[]=patient');
  expect(reception.status()).toBe(200);
  await expect(reception.text()).resolves.not.toContain('TypeError');
});

test('rejects an attacker-chosen session id and ignores URL session ids', async ({ page }) => {
  await page.goto('/login.php');
  const origin = new URL(page.url()).origin;
  const chosenId = 'attackerchosenvalidsessionid123456';

  await page.context().clearCookies();
  await page.context().addCookies([{
    name: 'MEDISHIELD_SID',
    value: chosenId,
    url: origin,
    httpOnly: true,
    sameSite: 'Strict'
  }]);
  await page.goto(`/login.php?MEDISHIELD_SID=${chosenId}`);

  const sessionCookie = (await page.context().cookies(origin))
    .find((cookie) => cookie.name === 'MEDISHIELD_SID');
  expect(sessionCookie).toBeDefined();
  expect(sessionCookie.value).not.toBe(chosenId);
});

test('revokes pending MFA after an account status cycle', async ({ page, browser }) => {
  const mailDir = path.join(__dirname, '..', 'test-results', 'mail');
  const messagesBefore = fs.readdirSync(mailDir).length;

  await page.goto('/login.php');
  await page.getByLabel('Email').fill('ui.pending-mfa-probe@medishield.test');
  await page.getByLabel('Password').fill('UiTest!2026A');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Enter your code' })).toBeVisible();
  const otpMessage = await readNewMail(mailDir, messagesBefore);
  const code = otpMessage.match(/code is: ([A-Z0-9]+)/)[1];

  const adminContext = await browser.newContext();
  const adminPage = await adminContext.newPage();
  await loginWithOtp(adminPage, 'ui.admin@medishield.test');
  await adminPage.goto('/admin/users.php');
  const probeRow = adminPage.getByRole('row').filter({ hasText: 'ui.pending-mfa-probe@medishield.test' });
  const probeId = (await probeRow.locator('td').first().textContent()).trim();
  await probeRow.getByRole('button', { name: 'Deactivate' }).click();
  await probeRow.getByRole('button', { name: 'Activate' }).click();

  await page.getByLabel('Verification code').fill(code);
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(page.getByText('Your sign-in state changed. Please sign in again.')).toBeVisible();

  await adminPage.goto('/admin/audit.php');
  const revocation = adminPage.getByRole('row')
    .filter({ hasText: 'OTP_FAILED' })
    .filter({ hasText: 'BLOCKED' })
    .filter({ hasText: probeId })
    .first();
  await expect(revocation).toBeVisible();
  await adminContext.close();
});

test('does not revive an authenticated session after deactivate and reactivate', async ({ page, browser }) => {
  await loginWithOtp(page, 'ui.session-probe@medishield.test');
  await expect(page.getByRole('heading', { name: 'Patient dashboard' })).toBeVisible();

  const adminContext = await browser.newContext();
  const adminPage = await adminContext.newPage();
  await loginWithOtp(adminPage, 'ui.admin@medishield.test');
  await adminPage.goto('/admin/users.php');
  const probeRow = adminPage.getByRole('row').filter({ hasText: 'ui.session-probe@medishield.test' });
  const probeId = (await probeRow.locator('td').first().textContent()).trim();
  await probeRow.getByRole('button', { name: 'Deactivate' }).click();
  await probeRow.getByRole('button', { name: 'Activate' }).click();

  await page.reload();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();

  await adminPage.goto('/admin/audit.php');
  const revokedLogout = adminPage.getByRole('row')
    .filter({ hasText: 'LOGOUT' })
    .filter({ hasText: 'BLOCKED' })
    .filter({ hasText: probeId })
    .first();
  await expect(revokedLogout).toBeVisible();
  await adminContext.close();
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

  await logout(page);
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
