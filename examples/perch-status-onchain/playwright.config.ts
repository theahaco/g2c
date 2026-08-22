import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  reporter: [['list']],
  timeout: 120_000,
  use: {
    baseURL: 'http://localhost:5178',
    viewport: { width: 1200, height: 1500 },
    // Settle entrance animations so full-page snapshots aren't caught mid-fade.
    reducedMotion: 'reduce',
  },
  webServer: {
    command: 'npx vite --port 5178 --strictPort',
    url: 'http://localhost:5178',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
