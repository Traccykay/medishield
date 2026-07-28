const { test, expect } = require('@playwright/test');
const { loginWithOtp } = require('./helpers');

test.describe.configure({ mode: 'serial' });

let otherVisitUrl;

test('receptionist creates immutable visit charges and records a cash receipt', async ({ page }) => {
  await loginWithOtp(page, 'ui.receptionist@medishield.test');
  await page.goto('/payments.php');

  await expect(page.getByRole('heading', { name: 'Billing and payments' })).toBeVisible();
  const billingPatient = page.getByRole('row').filter({ hasText: 'UI Billing Patient' });
  const otherPatient = page.getByRole('row').filter({ hasText: 'UI Other Billing Patient' });
  otherVisitUrl = await otherPatient.getByRole('link', { name: 'Manage billing' }).getAttribute('href');
  await billingPatient.getByRole('link', { name: 'Manage billing' }).click();

  await expect(page.getByRole('heading', { name: 'Manage visit billing' })).toBeVisible();
  await expect(page.getByText('UI Billing Patient')).toBeVisible();
  await page.getByLabel('Charge type').selectOption('service');
  await page.getByLabel('Catalogue item').selectOption('Blood glucose');
  await page.getByLabel('Quantity').fill('2');
  await page.getByRole('button', { name: 'Add charge' }).click();

  await expect(page.getByRole('cell', { name: 'Blood glucose' })).toBeVisible();
  await expect(page.getByText('KES 800', { exact: true })).toBeVisible();
  await expect(page.getByText('Total: KES 800')).toBeVisible();
  await page.getByLabel('Payment reference').fill('CASH-UI-001');
  await page.getByLabel('Receipt number').fill('RCT-UI-001');
  await page.getByRole('button', { name: 'Record payment' }).click();

  await expect(page.getByText('Payment recorded.')).toBeVisible();
  await expect(page.getByText('Payment status: paid')).toBeVisible();
  await expect(page.getByText('RCT-UI-001')).toBeVisible();

  await page.goto(otherVisitUrl);
  await page.getByLabel('Charge type').selectOption('service');
  await page.getByLabel('Catalogue item').selectOption('Blood glucose');
  await page.getByRole('button', { name: 'Add charge' }).click();
  await page.getByLabel('Payment status').selectOption('pending_insurance');
  await page.getByLabel('Payment reference').fill('CLAIM-UI-001');
  await page.getByRole('button', { name: 'Record payment' }).click();

  await expect(page.getByText('Payment recorded.')).toBeVisible();
  await expect(page.getByText('Payment status: pending_insurance')).toBeVisible();
  await expect(page.getByText('CLAIM-UI-001')).toBeVisible();
});

test('patient sees only their paid bill and forged mutation does not change it', async ({ page }) => {
  await loginWithOtp(page, 'ui.billing-patient@medishield.test');
  await page.goto('/payments.php');

  await expect(page.getByRole('heading', { name: 'My billing' })).toBeVisible();
  await expect(page.getByRole('heading', { name: /UI Billing Patient · Visit #1/ })).toBeVisible();
  await expect(page.getByText('Blood glucose')).toBeVisible();
  await expect(page.getByText('Total: KES 800')).toBeVisible();
  await expect(page.getByText('RCT-UI-001')).toBeVisible();

  await page.goto(otherVisitUrl);
  await expect(page.getByText('UI Other Billing Patient')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: /UI Billing Patient · Visit #1/ })).toBeVisible();

  const response = await page.request.post('/payments.php', {
    form: {
      action: 'add_charge',
      visit_id: '1',
      charge_type: 'medication',
      catalogue_item: 'Paracetamol 500 mg',
      quantity: '1'
    }
  });
  expect(await response.text()).toContain('Your session has expired. Please try again.');
  await page.goto('/payments.php');
  await expect(page.getByText('Total: KES 800')).toBeVisible();
  await expect(page.getByText('Paracetamol 500 mg')).toHaveCount(0);
});
