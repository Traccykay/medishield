const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const password = 'UiTest!2026A';
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

function uiDatabaseProbe(mode, argument = '0') {
  const probe = `
use MediShield\\Database\\Connection;
use MediShield\\Support\\DisposableDatabase;
$root = $argv[1];
$mode = $argv[2];
require $root . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
$configPath = $root . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'config.php';
$config = require $configPath;
$database = DisposableDatabase::requireUiTestName(
    (string) (getenv('MEDISHIELD_DB_NAME') ?: 'medishield_ui_test')
);
$config['db']['name'] = $database;
$pdo = Connection::fromConfig($config);
if ($mode === 'fingerprint') {
    $tables = $pdo->query(
        "SELECT TABLE_NAME
         FROM information_schema.TABLES
         WHERE TABLE_SCHEMA = DATABASE()
           AND TABLE_TYPE = 'BASE TABLE'
           AND TABLE_NAME <> 'audit_logs'
         ORDER BY TABLE_NAME"
    )->fetchAll(PDO::FETCH_COLUMN);
    $fingerprint = [];
    foreach ($tables as $table) {
        $tick = chr(96);
        $quoted = $tick . str_replace($tick, $tick . $tick, (string) $table) . $tick;
        $row = $pdo->query('CHECKSUM TABLE ' . $quoted)->fetch(PDO::FETCH_ASSOC);
        $fingerprint[(string) $table] = $row['Checksum'] ?? null;
    }
    echo json_encode($fingerprint, JSON_THROW_ON_ERROR);
    exit;
}
if ($mode === 'latest-audit-id') {
    echo json_encode((int) $pdo->query('SELECT COALESCE(MAX(log_id), 0) FROM audit_logs')->fetchColumn());
    exit;
}
if ($mode === 'audit-after') {
    $statement = $pdo->prepare(
        'SELECT log_id, user_id, user_role, action, module, status, anomaly_flag,
                affected_record_id, attempted_identifier
         FROM audit_logs
         WHERE log_id > :log_id
         ORDER BY log_id ASC'
    );
    $statement->execute([':log_id' => (int) $argv[3]]);
    echo json_encode($statement->fetchAll(PDO::FETCH_ASSOC), JSON_THROW_ON_ERROR);
    exit;
}
throw new RuntimeException('Unknown UI database probe mode.');
`;
  const output = execFileSync('php', ['-r', probe, root, mode, String(argument)], {
    cwd: root,
    env: {
      ...process.env,
      MEDISHIELD_DB_NAME: process.env.MEDISHIELD_DB_NAME || 'medishield_ui_test'
    }
  });

  return JSON.parse(output.toString('utf8'));
}

function domainFingerprint() {
  return uiDatabaseProbe('fingerprint');
}

function latestAuditId() {
  return uiDatabaseProbe('latest-audit-id');
}

function auditEventsAfter(logId) {
  return uiDatabaseProbe('audit-after', logId);
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

async function logout(page) {
  await page.getByRole('button', { name: 'Log out', exact: true }).first().click();
  await page.getByRole('heading', { name: 'Sign in' }).waitFor();
}

module.exports = {
  auditEventsAfter,
  domainFingerprint,
  latestAuditId,
  loginWithOtp,
  logout,
  readNewMail,
  resetUiDatabase,
  seedDashboardData
};
