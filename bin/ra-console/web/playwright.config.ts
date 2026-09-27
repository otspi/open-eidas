// Tests de bout en bout du frontend (docs/UI-UX.md) contre une console réelle :
// `cargo run --example e2e_console` monte ra-console (assets embarqués,
// en-têtes de sécurité) sur PostgreSQL, avec un opérateur dont la clé est
// confiée à l'authentificateur WebAuthn virtuel du navigateur.
//
// Exige OE_CASTORE_TEST_DSN. En local, PW_CHANNEL=chrome utilise le Chrome
// installé plutôt qu'un navigateur téléchargé par Playwright.

import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";

const port = Number(process.env.E2E_PORT ?? "8431");
const origin = `http://localhost:${port}`;
const repo = resolve(import.meta.dirname, "../../..");
export const fixturePath = resolve(repo, "target/e2e-fixture.json");

export default defineConfig({
  testDir: "e2e",
  workers: 1,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: origin,
    trace: "retain-on-failure",
    ...(process.env.PW_CHANNEL ? { channel: process.env.PW_CHANNEL } : {}),
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "cargo run -q -p ra-console --example e2e_console",
    cwd: repo,
    url: `${origin}/api/v1/console`,
    timeout: 900_000,
    reuseExistingServer: false,
    stdout: "pipe",
    stderr: "pipe",
    env: {
      OE_CASTORE_TEST_DSN: process.env.OE_CASTORE_TEST_DSN ?? "",
      E2E_PORT: String(port),
      E2E_FIXTURE: fixturePath,
    },
  },
});
