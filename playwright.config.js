const { defineConfig } = require('@playwright/test');
const path = require('node:path');

const demoMode = process.env.MEDISHIELD_DEMO === '1';

module.exports = defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global-setup.js',
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: 'http://127.0.0.1:8765',
    headless: !demoMode,
    launchOptions: demoMode ? { slowMo: 650 } : undefined,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: demoMode ? 'on' : 'retain-on-failure'
  },
  webServer: {
    command: 'php -S 127.0.0.1:8765 -t public',
    url: 'http://127.0.0.1:8765/login.php',
    reuseExistingServer: false,
    env: {
      MEDISHIELD_DB_NAME: 'medishield_ui_test',
      MEDISHIELD_MAIL_DUMP_DIR: path.join(__dirname, 'test-results', 'mail')
    }
  }
});
