// Dossiers d'incident dans le navigateur (docs/WEBUI.md §6, §15 étape 5c,
// docs/UI-UX.md §1) : alice ouvre un dossier, y consigne une note et la
// référence d'une action figée par l'autorité, puis le clôt en signant avec sa
// clé le corps exact affiché. Un administrateur le lit sans pouvoir y écrire.

import { expect, test, type Page } from "@playwright/test";
import { collectErrors, fixture, logIn, withOperatorKey } from "./helpers";

interface Incident {
  id: string;
  title: string;
  state: string;
  closed_by: string | null;
  closing_note: string | null;
}

async function incidents(page: Page, state: string): Promise<Incident[]> {
  return (await (await page.request.get(`/api/v1/incidents?state=${state}`)).json()) as Incident[];
}

const TITLE = "Signalement CERT-FR 2026-991";
const NOTE = "faux positif : clé intacte, constat joint";

test("ouvrir un dossier, y consigner, le clore en signant", async ({ page }) => {
  const errors = collectErrors(page);
  await withOperatorKey(page);
  await page.goto("/");
  await logIn(page);
  await expect(page.getByTestId("count-incidents")).toHaveText("(0)");
  await page.getByTestId("nav-incidents").click();

  // Ouverture.
  await page.getByTestId("incident-title").fill(TITLE);
  await page.getByTestId("incident-open-submit").click();
  await expect(page.getByTestId("incidents-status")).toHaveText("Dossier ouvert.");
  await expect(page.getByTestId("count-incidents")).toHaveText("(1)");
  const opened = (await incidents(page, "OUVERT")).find((i) => i.title === TITLE)!;
  await expect(page.getByTestId(`incident-${opened.id}`)).toContainText(fixture().operator);
  await expect(page.getByTestId("incident-state")).toContainText("ouvert");

  // Une note, sur deux lignes.
  await page.getByTestId("note").fill("signalement reçu à 9 h\nclé TSU à vérifier");
  await page.getByTestId("note-submit").click();
  await expect(page.getByTestId("entry-note")).toContainText("clé TSU à vérifier");

  // Une action que l'autorité a figée (ici, une approbation préparée et non
  // signée) : le dossier la désigne, avec l'empreinte relue chez l'autorité.
  const prepared = (await (
    await page.request.post("/api/v1/webauthn/challenge", {
      data: { action: "approve_request", transaction_id: fixture().pending[7]!, csr_fingerprint: `empreinte-${fixture().pending[7]!}`, comment: "liée au dossier" },
    })
  ).json()) as { action_id: string; body_hash: string };
  await page.getByTestId("link-action").fill(prepared.action_id);
  await page.getByTestId("link-comment").fill("demande concernée par le signalement");
  await page.getByTestId("link-submit").click();
  const linked = page.getByTestId("entry-action");
  await expect(linked).toContainText("Approbation d'une demande");
  await expect(linked).toContainText("non exécutée");
  await expect(linked).toContainText(prepared.action_id);
  await expect(linked).toContainText(prepared.body_hash.slice(0, 8));

  // Une action inconnue n'entre pas dans le dossier.
  await page.getByTestId("link-action").fill("00000000-0000-4000-8000-000000000000");
  await page.getByTestId("link-submit").click();
  await expect(page.getByTestId("incidents-status")).toContainText("Aucune action");
  await expect(page.getByTestId("entry-action")).toHaveCount(1);

  // Clôture : justification obligatoire, puis le corps figé et son empreinte.
  await page.getByTestId("close").click();
  await page.getByTestId("closing-next").click();
  await expect(page.getByTestId("closing-dialog")).toBeVisible();
  await page.getByTestId("closing-note-input").fill(NOTE);
  await page.getByTestId("closing-next").click();
  const body = page.getByTestId("frozen-body");
  await expect(body).toContainText(`"incident_id":"${opened.id}"`);
  await expect(body).toContainText(`"closing_note":"${NOTE}"`);
  await expect(body).toContainText(`"operator":"${fixture().operator}"`);
  await expect(page.getByTestId("body-hash")).toHaveText(/^([0-9a-f]{8} ){7}[0-9a-f]{8}$/);
  // Rien n'est clos tant que rien n'est signé.
  expect((await incidents(page, "CLOS")).some((i) => i.id === opened.id)).toBe(false);

  await page.getByTestId("sign").click();
  await expect(page.getByTestId("sign-dialog")).toBeHidden();
  await expect(page.getByTestId("incidents-status")).toHaveText("Dossier clos.");
  await expect(page.getByTestId("incident-state")).toContainText("clos");
  await expect(page.getByTestId("closing-note")).toHaveText(NOTE);
  await expect(page.getByTestId("count-incidents")).toHaveText("(0)");
  // Clos : plus rien à consigner.
  await expect(page.getByTestId("note")).toHaveCount(0);
  await expect(page.getByTestId("close")).toHaveCount(0);

  const closed = (await incidents(page, "CLOS")).find((i) => i.id === opened.id)!;
  expect(closed.closed_by).toBe(fixture().operator);
  expect(closed.closing_note).toBe(NOTE);
  expect(errors).toEqual([]);
});

test("un administrateur lit les dossiers sans pouvoir y écrire", async ({ page }) => {
  await withOperatorKey(page, "root");
  await page.goto("/");
  await logIn(page, "root");
  await page.getByTestId("nav-incidents").click();
  await expect(page.getByTestId("incident-open")).toHaveCount(0);

  await page.getByTestId("incident-filter").selectOption("CLOS");
  const closed = (await incidents(page, "CLOS")).find((i) => i.title === TITLE)!;
  await page.getByTestId(`incident-${closed.id}`).click();
  await expect(page.getByTestId("closing-note")).toHaveText(NOTE);
  await expect(page.getByTestId("timeline")).toContainText("clé TSU à vérifier");

  // Et la console refuse ce que l'écran ne propose pas.
  const refused = await page.request.post("/api/v1/incidents", { data: { title: "sans le rôle" } });
  expect(refused.status()).toBe(403);
  expect((await incidents(page, "OUVERT")).length).toBe(0);
});
