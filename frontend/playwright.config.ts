import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: 'list',
  use: { baseURL: 'http://localhost:4173', browserName: 'chromium', trace: 'retain-on-failure' },
  webServer: [
    {
      command:
        '.venv/bin/uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8189 --no-access-log',
      cwd: '../backend',
      url: 'http://127.0.0.1:8189/health/live',
      reuseExistingServer: false,
    },
    {
      command: 'npm run dev -- --host 127.0.0.1 --port 4173 --strictPort',
      env: { SMON_API_PROXY: 'http://127.0.0.1:8189' },
      url: 'http://localhost:4173',
      reuseExistingServer: false,
    },
  ],
});
