// Explorateur d'audit dans le navigateur (docs/WEBUI.md §7, §15 étape 6d,
// docs/UI-UX.md §3.3) : les deux journaux (autorité et console) sont relus et
// vérifiés par la console avant tout affichage ; une chaîne rompue bloque tout.

import { expect, test } from "@playwright/test";
import { collectErrors, fixture, logIn, withOperatorKey } from "./helpers";

test("recherche dans les deux journaux, filtres et détail d'un événement", async ({ page }) => {
  const serial = fixture().certificates[0]!;
  const errors = collectErrors(page);
  await withOperatorKey(page);
  await page.goto("/");
  await logIn(page);
  await page.getByTestId("nav-audit").click();

  // 3 événements de l'autorité + 2 de la console, tous intègres.
  await expect(page.getByTestId("audit-verified")).toContainText("5 entrées intègres");
  await expect(page.getByTestId("audit-results").locator("tbody tr:not(.detail)")).toHaveCount(5);
  await expect(page.getByTestId("audit-results")).toContainText("Autorité");
  await expect(page.getByTestId("audit-results")).toContainText("Console");

  // Filtre par série : l'API ne retient que les événements de ce certificat.
  await page.getByTestId("audit-serial").fill(serial.toUpperCase());
  await page.getByTestId("audit-submit").click();
  await expect(page.getByTestId("audit-count")).toHaveText("2 résultat(s)");
  await expect(page.getByTestId("audit-results")).not.toContainText("ra.login_succeeded");

  // Filtre par opérateur, dans le navigateur, sur les résultats reçus.
  await page.getByTestId("audit-operator").fill("BOB");
  await expect(page.getByTestId("audit-count")).toHaveText("1 résultat(s) sur 2 reçus");
  await expect(page.getByTestId("audit-results")).toContainText("ca.certificate_revoked");
  await expect(page.getByTestId("audit-results")).not.toContainText("ca.certificate_issued");

  // Détail : le contenu de l'événement, en texte (jamais interprété).
  const detail = page.locator("[data-testid^=audit-detail-ca-server-]");
  await expect(detail.first()).toBeHidden();
  await page.locator("[data-testid^=audit-toggle-ca-server-]").first().click();
  await expect(detail.first()).toBeVisible();
  await expect(detail.first()).toContainText('"commentaire": "remplacé"');

  // Filtre par type d'événement.
  await page.getByTestId("audit-operator").fill("");
  await page.getByTestId("audit-event").selectOption("ca.certificate_issued");
  await expect(page.getByTestId("audit-count")).toHaveText("1 résultat(s) sur 2 reçus");
  expect(errors).toEqual([]);
});

test("une chaîne rompue bloque tout l'affichage", async ({ page }) => {
  const { s3 } = fixture();
  const url = `${s3.endpoint}/${s3.bucket}/${s3.ca_key}`;
  const original = await (await page.request.get(url)).body();
  const altered = Buffer.from(original.toString("utf8").replace("tsu-rev-1", "tsu-rev-X"));
  expect(altered.equals(original)).toBe(false);

  await withOperatorKey(page);
  await page.goto("/");
  await logIn(page);
  await page.getByTestId("nav-audit").click();
  await expect(page.getByTestId("audit-verified")).toBeVisible();

  try {
    await page.request.put(url, { data: altered });
    await page.getByTestId("audit-submit").click();
    const alert = page.getByTestId("audit-broken");
    await expect(alert).toContainText("RUPTURE D'INTÉGRITÉ");
    await expect(alert).toHaveAttribute("role", "alert");
    // Rien n'est montré à côté de l'alerte, pas même les événements de la console.
    await expect(page.getByTestId("audit-results")).toBeHidden();
    await expect(page.getByTestId("audit-verified")).toHaveCount(0);
  } finally {
    await page.request.put(url, { data: original });
  }

  await page.getByTestId("audit-submit").click();
  await expect(page.getByTestId("audit-verified")).toContainText("5 entrées intègres");
  await expect(page.getByTestId("audit-broken")).toHaveCount(0);
});
