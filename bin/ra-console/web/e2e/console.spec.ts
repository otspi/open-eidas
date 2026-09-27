// Parcours de la console dans un vrai navigateur (docs/WEBUI.md §15 étape 6a,
// docs/UI-UX.md §6.3) : en-têtes de sécurité, connexion par clé FIDO2,
// déconnexion, verrouillage après inactivité.

import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fixturePath } from "../playwright.config";

interface Fixture {
  operator: string;
  credential: Record<string, unknown> & { signCount: number };
}

const fixture = (): Fixture => JSON.parse(readFileSync(fixturePath, "utf8")) as Fixture;

// Chaque test recrée un authentificateur : son compteur doit dépasser celui
// déjà vu par la console, sans quoi elle détecte (à juste titre) un clone.
let signCountBase = 1000;

async function withOperatorKey(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      // La clé de test a été enregistrée par le SoftToken, qui s'annonce
      // `internal` : le navigateur ne consulte que les authentificateurs de
      // ce transport (les options relaient les transports enregistrés).
      transport: "internal",
      hasResidentKey: false,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  signCountBase += 1000;
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId,
    credential: { ...fixture().credential, signCount: fixture().credential.signCount + signCountBase },
  } as never);
}

/// Exceptions de la page et violations de CSP : aucune n'est admise. Les
/// réponses d'erreur HTTP attendues (401 avant connexion) n'en sont pas.
function collectErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(e.message));
  return errors;
}

async function logIn(page: Page): Promise<void> {
  await page.getByTestId("login-name").fill(fixture().operator);
  await page.getByTestId("login-submit").click();
  await expect(page.getByTestId("operator")).toHaveText(fixture().operator);
}

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
  await expect(page.getByTestId("count-requests")).toHaveText("(0)");
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
