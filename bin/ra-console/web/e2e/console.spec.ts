// Parcours de la console dans un vrai navigateur (docs/WEBUI.md §15 étape 6a,
// docs/UI-UX.md §6.3) : en-têtes de sécurité, connexion par clé FIDO2,
// déconnexion, verrouillage après inactivité.

import { expect, test } from "@playwright/test";
import { collectErrors, logIn, withOperatorKey } from "./helpers";

test("chaque réponse porte les en-têtes de sécurité, sans script en ligne", async ({ request }) => {
  for (const path of ["/", "/assets/console.js", "/api/v1/console", "/api/v1/me"]) {
    const res = await request.get(path);
    const headers = res.headers();
    expect(headers["content-security-policy"], path).toContain("script-src 'self'");
    expect(headers["content-security-policy"], path).toContain("frame-ancestors 'none'");
    expect(headers["x-frame-options"], path).toBe("DENY");
    expect(headers["x-content-type-options"], path).toBe("nosniff");
    expect(headers["cache-control"], path).toBe("no-store");
  }
  const html = await (await request.get("/")).text();
  expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/);
  expect(html).not.toMatch(/\sstyle=/);
});

test("connexion par clé FIDO2, puis déconnexion qui révoque la session", async ({ page }) => {
  const errors = collectErrors(page);
  await withOperatorKey(page);
  await page.goto("/");
  await expect(page.getByTestId("env-banner")).toHaveText("STAGING");
  await logIn(page);
  await expect(page.getByTestId("role")).toHaveText("opérateur RA");
  await expect(page.getByTestId("count-requests")).toHaveText(/^\(\d+\)$/);
  await expect(page.getByTestId("count-quorum")).toHaveText("(0)");

  await page.getByTestId("logout").click();
  await expect(page.getByTestId("login-name")).toBeVisible();
  expect((await page.request.get("/api/v1/me")).status()).toBe(401);
  expect(errors).toEqual([]);
});

test("verrouillage après 15 minutes d'inactivité", async ({ page }) => {
  await page.clock.install();
  await withOperatorKey(page);
  await page.goto("/");
  await logIn(page);

  await page.clock.fastForward("14:00");
  await expect(page.getByTestId("idle-warning")).toBeVisible();
  await page.clock.fastForward("01:00");
  await expect(page.getByTestId("login-status")).toContainText("verrouillée");
  expect((await page.request.get("/api/v1/me")).status()).toBe(401);
});
