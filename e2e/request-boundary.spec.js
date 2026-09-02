const { test, expect } = require('@playwright/test');
const {
  auditEventsAfter,
  domainFingerprint,
  latestAuditId,
  loginWithOtp,
  resetUiDatabase
} = require('./helpers');

test.describe.configure({ mode: 'serial' });

const csrfVariants = [
  { name: 'missing token', kind: 'missing' },
  { name: 'wrong token', kind: 'wrong' },
  { name: 'array token', kind: 'array' }
];

const routesByActor = {
  guest: [
    {
      path: '/login.php',
      module: 'auth',
      fields: { email: 'ui.login-probe@medishield.test', password: 'Incorrect!2026' }
    },
    {
      path: '/forgot_password.php',
      module: 'auth',
      fields: { email: 'ui.doctor@medishield.test' }
    },
    {
      path: '/activate.php',
      module: 'auth',
      fields: {
        password: 'Replacement!Pass2026',
        confirm_password: 'Replacement!Pass2026'
      }
    }
  ],
  admin: [
    {
      path: '/admin/assign_patient.php',
      module: 'patients',
      fields: { patient_id: '1', staff_user_id: '1', assignment_action: 'assign' },
      arrayFields: ['patient_id', 'staff_user_id']
    },
    {
      path: '/admin/create_user.php',
      module: 'admin',
      fields: {
        full_name: 'CSRF Boundary User',
        email: 'csrf-boundary-user@medishield.test',
        role: 'patient'
      },
      arrayFields: ['full_name']
    },
    {
      path: '/admin/reset_password.php',
      module: 'admin',
      fields: { user_id: '1' },
      arrayFields: ['user_id']
    },
    {
      path: '/admin/users.php',
      module: 'admin',
      fields: { user_id: '1', status: 'inactive' },
      arrayFields: ['user_id']
    },
    {
      path: '/change_password.php',
      module: 'auth',
      fields: {
        current_password: 'UiTest!2026A',
        new_password: 'Boundary!Pass2026',
        confirm_password: 'Boundary!Pass2026'
      },
      arrayFields: ['current_password']
    },
    {
      path: '/logout.php',
      module: 'auth',
      fields: {}
    }
  ],
  doctor: [
    {
      path: '/doctor/add_diagnosis.php',
      module: 'doctor',
      fields: { patient_id: '1', visit_id: '1', diagnosis: 'Must not be written' },
      arrayFields: ['patient_id', 'visit_id']
    },
    {
      path: '/doctor/issue_prescription.php',
      module: 'doctor',
      fields: {
        patient_id: '1',
        record_id: '1',
        visit_id: '1',
        medication: 'Paracetamol 500 mg',
        dosage: '1 tablet'
      },
      arrayFields: ['patient_id', 'record_id', 'visit_id']
    },
    {
      path: '/doctor/request_lab.php',
      module: 'doctor',
      fields: {
        patient_id: '1',
        record_id: '1',
        visit_id: '1',
        test_name: 'Full Blood Count'
      },
      arrayFields: ['patient_id', 'record_id', 'visit_id']
    }
  ],
  lab: [
    {
      path: '/lab/upload_result.php',
      module: 'lab',
      fields: { lab_request_id: '1', result: 'Must not be written' },
      arrayFields: ['lab_request_id']
    }
  ],
  nurse: [
    {
      path: '/nurse/add_vitals.php',
      module: 'nurse',
      fields: {
        patient_id: '1',
        visit_id: '1',
        temperature_c: '37',
        systolic_mmhg: '120',
        diastolic_mmhg: '80',
        pulse_bpm: '70',
        weight_kg: '65'
      },
      arrayFields: ['patient_id', 'visit_id']
    },
    {
      path: '/nurse/assign_doctor.php',
      module: 'nurse',
      fields: { patient_id: '1', visit_id: '1', doctor_id: '1' },
      arrayFields: ['patient_id', 'visit_id', 'doctor_id']
    },
    {
      path: '/nurse/triage.php',
      module: 'triage',
      fields: { visit_id: '1' },
      arrayFields: ['visit_id']
    }
  ],
  pharmacist: [
    {
      path: '/pharmacy/dispense.php',
      module: 'pharmacy',
      fields: { prescription_id: '1', status: 'dispensed', remarks: 'Must not be written' },
      arrayFields: ['prescription_id']
    }
  ],
  receptionist: [
    {
      path: '/payments.php',
      module: 'billing',
      fields: {
        visit_id: '1',
        action: 'add_charge',
        charge_type: 'service',
        catalogue_item: 'Full Blood Count',
        quantity: '1'
      },
      arrayFields: ['visit_id']
    },
    {
      path: '/reception/intake.php',
      module: 'reception',
      fields: { patient_id: '1', payment_method: 'cash', insurer: '' },
      arrayFields: ['patient_id']
    },
    {
      path: '/register_patient.php',
      module: 'patients',
      fields: {
        user_id: '',
        full_name: 'CSRF Boundary Patient',
        date_of_birth: '1990-01-01',
        gender: 'female',
        phone: '0712345678',
        emergency_contact: 'Boundary Contact 0712345679'
      },
      arrayFields: ['user_id', 'full_name']
    }
  ]
};

function formBody(fields, csrfVariant, validToken = null, arrayFields = []) {
  const body = new URLSearchParams();
  for (const [name, value] of Object.entries(fields)) {
    if (arrayFields.includes(name)) {
      body.append(`${name}[]`, value);
    } else {
      body.append(name, value);
    }
  }
  if (validToken !== null) {
    body.append('csrf_token', validToken);
  } else if (csrfVariant.kind === 'wrong') {
    body.append('csrf_token', 'wrong-token');
  } else if (csrfVariant.kind === 'array') {
    body.append('csrf_token[]', 'attacker-controlled');
  }
  return body.toString();
}

async function postForm(page, route, body) {
  return page.request.post(route, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: body,
    maxRedirects: 0
  });
}

async function expectCsrfRejection(page, route, actorRole) {
  for (const variant of csrfVariants) {
    const stateBefore = domainFingerprint();
    const auditId = latestAuditId();
    const response = await postForm(page, route.path, formBody(route.fields, variant));

    expect(response.status(), `${route.path}: ${variant.name}`).toBe(403);
    await expect(response.text()).resolves.toBe('Request could not be processed.');
    expect(domainFingerprint(), `${route.path}: ${variant.name} changed domain state`)
      .toEqual(stateBefore);

    const events = auditEventsAfter(auditId);
    expect(events, `${route.path}: ${variant.name} audit count`).toHaveLength(1);
    expect(events[0]).toMatchObject({
      user_role: actorRole,
      action: 'CSRF_REJECTED',
      module: route.module,
      status: 'BLOCKED',
      anomaly_flag: 'SUSPICIOUS',
      affected_record_id: null,
      attempted_identifier: null
    });
  }
}

async function expectArrayIdsFailClosed(page, route) {
  if (!route.arrayFields) {
    return;
  }

  await page.goto('/change_password.php');
  const csrfToken = await page.locator('input[name="csrf_token"]').first().inputValue();
  const stateBefore = domainFingerprint();
  const response = await postForm(
    page,
    route.path,
    formBody(route.fields, { kind: 'valid' }, csrfToken, route.arrayFields)
  );

  expect(response.status(), `${route.path}: array identifier`).toBeLessThan(500);
  await expect(response.text()).resolves.not.toContain('TypeError');
  expect(domainFingerprint(), `${route.path}: array identifier changed domain state`)
    .toEqual(stateBefore);
}

async function becomeGuest(page) {
  await page.context().clearCookies();
  await page.goto('/login.php');
}

test.beforeAll(() => {
  resetUiDatabase();
});

test('all mutation controllers reject hostile CSRF before parsing or domain work', async ({ page }) => {
  test.setTimeout(300_000);
  await becomeGuest(page);
  for (const route of routesByActor.guest) {
    await expectCsrfRejection(page, route, 'guest');
  }

  await page.goto('/login.php');
  await page.getByLabel('Email').fill('ui.pending-mfa-probe@medishield.test');
  await page.getByLabel('Password').fill('UiTest!2026A');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Enter your code' })).toBeVisible();
  await expectCsrfRejection(page, {
    path: '/verify_otp.php',
    module: 'auth',
    fields: { otp: 'ATTACKER' }
  }, 'guest');

  const authenticatedActors = [
    ['admin', 'ui.admin@medishield.test'],
    ['doctor', 'ui.doctor@medishield.test'],
    ['lab', 'ui.lab@medishield.test'],
    ['nurse', 'ui.nurse@medishield.test'],
    ['pharmacist', 'ui.pharmacist@medishield.test'],
    ['receptionist', 'ui.receptionist@medishield.test']
  ];

  for (const [role, email] of authenticatedActors) {
    await becomeGuest(page);
    await loginWithOtp(page, email);
    for (const route of routesByActor[role]) {
      await expectCsrfRejection(page, route, role);
      await expectArrayIdsFailClosed(page, route);
    }
  }
});

test('logout and administrator reset are POST-only and logout remains usable in navigation', async ({ page }) => {
  await becomeGuest(page);
  await loginWithOtp(page, 'ui.admin@medishield.test');

  for (const route of ['/logout.php', '/admin/reset_password.php']) {
    const stateBefore = domainFingerprint();
    const auditId = latestAuditId();
    const response = await page.request.get(route, { maxRedirects: 0 });

    expect(response.status()).toBe(405);
    await expect(response.text()).resolves.toBe('Request method not allowed.');
    expect(domainFingerprint()).toEqual(stateBefore);
    expect(auditEventsAfter(auditId)).toEqual([]);
  }

  await page.goto('/admin/dashboard.php');
  await expect(page.locator('a[href$="/logout.php"]')).toHaveCount(0);
  const logoutForms = page.locator('form[action$="/logout.php"]');
  await expect(logoutForms.first()).toBeVisible();
  await logoutForms.first().getByRole('button', { name: 'Log out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
});
