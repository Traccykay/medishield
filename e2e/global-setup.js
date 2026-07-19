const { execFileSync } = require('node:child_process');
const { rmSync, mkdirSync } = require('node:fs');
const path = require('node:path');

module.exports = () => {
  const root = path.resolve(__dirname, '..');
  const mailDir = path.join(root, 'test-results', 'mail');
  rmSync(path.join(root, 'test-results'), { recursive: true, force: true });
  mkdirSync(mailDir, { recursive: true });

  execFileSync('powershell.exe', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', path.join(root, 'scripts', 'setup-ui-test-db.ps1')
  ], { cwd: root, stdio: 'inherit' });

  execFileSync('php', [path.join(root, 'scripts', 'seed-ui-test-users.php')], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, MEDISHIELD_DB_NAME: 'medishield_ui_test' }
  });
};
