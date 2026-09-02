const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const password = 'UiTest!2026';
const mailDirectory = process.env.MEDISHIELD_MAIL_DUMP_DIR
  || path.join(__dirname, '..', 'test-results', 'mail');
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

function seedDashboardData() {
  execFileSync('php', [path.join(root, 'scripts', 'seed-ui-dashboard-data.php')], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, MEDISHIELD_DB_NAME: 'medishield_ui_test' }
  });
}

async function waitForMail(directory, count) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (fs.readdirSync(directory).length > count) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Timed out waiting for the OTP mail dump.');
}

async function readNewMail(directory, messagesBefore) {
  await waitForMail(directory, messagesBefore);
  const latest = fs.readdirSync(directory)
    .map((file) => ({ file, mtime: fs.statSync(path.join(directory, file)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)[0].file;

  return fs.readFileSync(path.join(directory, latest), 'utf8');
}

async function loginWithOtp(page, email, accountPassword = password) {
  const messagesBefore = fs.existsSync(mailDirectory) ? fs.readdirSync(mailDirectory).length : 0;
  await page.goto('/login.php');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(accountPassword);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('heading', { name: 'Enter your code' }).waitFor();

  const message = await readNewMail(mailDirectory, messagesBefore);
  const code = message.match(/code is: ([A-Z0-9]+)/)[1];
  await page.getByLabel('Verification code').fill(code);
  await page.getByRole('button', { name: 'Verify' }).click();
}

module.exports = {
  loginWithOtp,
  readNewMail,
  resetUiDatabase,
  seedDashboardData
};
