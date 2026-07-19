const fs = require('node:fs');
const path = require('node:path');

const password = 'UiTest!2026';

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

async function loginWithOtp(page, email) {
  const mailDir = path.join(__dirname, '..', 'test-results', 'mail');
  const messagesBefore = fs.existsSync(mailDir) ? fs.readdirSync(mailDir).length : 0;
  await page.goto('/login.php');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('heading', { name: 'Enter your code' }).waitFor();

  await waitForMail(mailDir, messagesBefore);
  const latest = fs.readdirSync(mailDir)
    .map((file) => ({ file, mtime: fs.statSync(path.join(mailDir, file)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)[0].file;
  const message = fs.readFileSync(path.join(mailDir, latest), 'utf8');
  const code = message.match(/code is: ([A-Z0-9]+)/)[1];
  await page.getByLabel('Verification code').fill(code);
  await page.getByRole('button', { name: 'Verify' }).click();
}

module.exports = { loginWithOtp };
