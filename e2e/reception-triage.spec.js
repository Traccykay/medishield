const { test, expect } = require('@playwright/test');
const { loginWithOtp } = require('./helpers');

test.describe.configure({ mode: 'serial' });

test('receptionist can search and start a patient triage visit', async ({ page }) => {
  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await expect(page.getByRole('heading', { name: 'Reception dashboard' })).toBeVisible();
  await page.goto('/doctor/dashboard.php');
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible();
  await page.goto('/reception/dashboard.php');

  const patientNumber = `UI-${Date.now()}`;
  await page.getByRole('link', { name: 'Register new patient' }).click();
  await page.getByLabel('Patient number').fill(patientNumber);
  await page.getByLabel('Full name').fill('UI Flow Patient');
  await page.getByLabel('Date of birth').fill('1990-01-01');
  await page.getByLabel('Gender').selectOption('female');
  await page.getByLabel('Phone').fill('0201234567');
  await page.getByLabel('Emergency contact').fill('Emergency Contact +254712345678');
  await page.getByRole('button', { name: 'Register patient' }).click();
  await expect(page.getByText('Phone must be a valid Kenyan mobile number.')).toBeVisible();
  await page.getByLabel('Phone').fill('0712345678');
  await page.getByRole('button', { name: 'Register patient' }).click();

  await expect(page.getByRole('heading', { name: 'Patient arrival' })).toBeVisible();
  await page.getByLabel('Payment method').selectOption('insurance');
  await page.getByLabel('Insurance provider (if applicable)').selectOption('AAR Insurance');
  await page.getByRole('button', { name: 'Add to triage queue' }).click();
  await expect(page.getByText('Waiting for triage')).toBeVisible();

  await page.getByPlaceholder('Name, patient number, or phone').fill(patientNumber);
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByRole('cell', { name: 'UI Flow Patient' }).first()).toBeVisible();
});

test('nurse can claim triage and record vitals', async ({ page }) => {
  await loginWithOtp(page, 'ui.nurse@medishield.test');
  await page.goto('/nurse/triage.php');
  await expect(page.getByRole('heading', { name: 'Triage queue' })).toBeVisible();
  await page.getByRole('button', { name: 'Start triage' }).first().click();
  await expect(page.getByRole('heading', { name: 'Record vitals' })).toBeVisible();

  await page.getByLabel('Temperature C').fill('37.1');
  await page.getByLabel('Systolic mmHg').fill('120');
  await page.getByLabel('Diastolic mmHg').fill('80');
  await page.getByLabel('Pulse bpm').fill('72');
  await page.getByLabel('Weight kg').fill('65');
  await page.getByLabel('Symptoms / observations').fill('Mild cough');
  await page.getByRole('button', { name: 'Save vitals' }).click();
  await expect(page.getByRole('heading', { name: 'Vitals history' })).toBeVisible();

  await page.goto('/nurse/dashboard.php');
  await page.getByRole('link', { name: 'Assign doctor' }).first().click();
  await page.getByLabel('Doctor').selectOption({
    label: 'UI Doctor (ui.doctor@medishield.test)'
  });
  await page.getByRole('button', { name: 'Assign doctor' }).click();

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.doctor@medishield.test');
  await expect(page.getByRole('heading', { name: 'Doctor dashboard' })).toBeVisible();
  await expect(page.getByText('UI Flow Patient')).toBeVisible();
});

test('clinical roles route lab results and prescriptions through billing', async ({ page }) => {
  await loginWithOtp(page, 'ui.doctor@medishield.test');
  await page.getByRole('link', { name: 'Open' }).click();
  await page.getByRole('link', { name: 'Add diagnosis' }).click();
  await page.getByLabel('Diagnosis').fill('Upper respiratory infection');
  await page.getByLabel('Treatment').fill('Rest and fluids');
  await page.getByRole('button', { name: 'Save diagnosis' }).click();

  await page.getByRole('link', { name: 'Request lab' }).click();
  await page.getByLabel('Test name and cost').selectOption('Blood glucose');
  await page.getByLabel('Reason').fill('Rule out elevated glucose');
  await page.getByRole('button', { name: 'Send to lab queue' }).click();

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.lab@medishield.test');
  await expect(page.getByRole('heading', { name: 'Laboratory dashboard' })).toBeVisible();
  await page.getByRole('link', { name: 'Open pending queue' }).click();
  await expect(page.getByRole('heading', { name: 'Lab requests' })).toBeVisible();
  await expect(page.getByText('Blood glucose')).toBeVisible();
  await page.getByRole('link', { name: 'Upload result' }).click();
  await page.getByLabel('Result').fill('5.2 mmol/L');
  await page.getByRole('button', { name: 'Complete request' }).click();
  await page.goto('/lab/dashboard.php');
  await page.getByRole('link', { name: 'View completed tests' }).click();
  await expect(page.getByText('Blood glucose')).toBeVisible();

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.doctor@medishield.test');
  await page.getByRole('link', { name: 'Open' }).click();
  await expect(page.getByText('5.2 mmol/L')).toBeVisible();
  await page.getByRole('link', { name: 'Issue prescription' }).click();
  await page.getByLabel('Medication and cost').selectOption('Paracetamol 500 mg');
  await page.getByLabel('Dosage').fill('One tablet every six hours');
  await page.getByLabel('Instructions').fill('Take after meals');
  await page.getByRole('button', { name: 'Send to pharmacy queue' }).click();
  await expect(page.getByRole('heading', { name: 'Patient medical history' })).toBeVisible();
  await expect(page.getByText('Upper respiratory infection')).toBeVisible();

  await page.goto('/logout.php');
  await loginWithOtp(page, 'ui.pharmacist@medishield.test');
  await expect(page.getByRole('heading', { name: 'Pharmacy dashboard' })).toBeVisible();
  await page.getByRole('link', { name: 'Open prescription queue' }).click();
  await expect(page.getByRole('heading', { name: 'Pending prescriptions' })).toBeVisible();
  await expect(page.getByText('KES 150')).toBeVisible();
  await page.getByRole('link', { name: 'Dispense' }).click();
  await expect(page.locator('p').filter({ hasText: 'Billable amount:' })).toContainText('KES 150');
  await expect(page.locator('p').filter({ hasText: 'Payment method:' })).toContainText('insurance');
  await page.getByRole('button', { name: 'Record outcome' }).click();
  await expect(page.getByText('No pending prescriptions.')).toBeVisible();
  await page.goto('/pharmacy/dashboard.php');
  await page.getByRole('link', { name: 'View dispensed history' }).click();
  await expect(page.getByText('Paracetamol 500 mg')).toBeVisible();
});

test('password recovery does not reveal whether an account exists', async ({ page }) => {
  await page.goto('/login.php');
  await page.getByRole('link', { name: 'Forgot password?' }).click();
  await page.getByLabel('Email').fill('ui.receptionist@medishield.test');
  await page.getByRole('button', { name: 'Send reset link' }).click();
  await expect(page.getByText('If that email belongs to an active account, a password reset link has been sent.')).toBeVisible();
  await page.getByLabel('Email').fill('unknown@medishield.test');
  await page.getByRole('button', { name: 'Send reset link' }).click();
  await expect(page.getByText('If that email belongs to an active account, a password reset link has been sent.')).toBeVisible();
});
