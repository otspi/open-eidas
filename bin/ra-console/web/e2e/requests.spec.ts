// Décisions RA signées dans le navigateur (docs/WEBUI.md §15 étape 6b,
// docs/UI-UX.md §3.1, §3.4) : la modale affiche le corps figé par ca-server et
// son empreinte, la clé signe, ca-server exécute ; au clavier comme à la souris.

import { expect, test, type Page } from "@playwright/test";
import { collectErrors, fixture, logIn, withOperatorKey } from "./helpers";

async function stateOf(page: Page, tx: string): Promise<{ state: string; operator: string | null } | undefined> {
  for (const state of ["PENDING", "APPROVED", "REJECTED"]) {
    const list = (await (await page.request.get(`/api/v1/requests?state=${state}`)).json()) as {
      transaction_id: string;
      state: string;
      operator: string | null;
    }[];
    const found = list.find((r) => r.transaction_id === tx);
    if (found) return found;
  }
  return undefined;
}

test("approuver une demande : corps figé affiché, signé, exécuté par ca-server", async ({ page }) => {
  const errors = collectErrors(page);
  const tx = fixture().pending[0]!;
  await withOperatorKey(page);
  await page.goto("/");
  await logIn(page);

  await page.getByTestId(`row-${tx}`).click();
  await page.getByTestId("approve").click();
  await page.getByTestId("comment").fill("identité vérifiée au guichet");
  await page.getByTestId("comment-next").click();

  // WYSIWYS : ce qui sera exécuté, tel que ca-server l'a figé, et son empreinte.
  const body = page.getByTestId("frozen-body");
  await expect(body).toContainText(`"transaction_id": "${tx}"`);
  await expect(body).toContainText(`"action": "approve_request"`);
  await expect(body).toContainText("identité vérifiée au guichet");
  await expect(page.getByTestId("body-hash")).toHaveText(/^([0-9a-f]{8} ){7}[0-9a-f]{8}$/);

  await page.getByTestId("sign").click();
  await expect(page.getByTestId("sign-dialog")).toBeHidden();
  await expect(page.getByTestId("requests-status")).toContainText(`${tx} approuvée`);
  await expect(page.getByTestId(`row-${tx}`)).toHaveCount(0);
  expect(await stateOf(page, tx)).toMatchObject({ state: "APPROVED", operator: fixture().operator });
  expect(errors).toEqual([]);
});

test("rejeter au clavier : motif obligatoire, puis signature", async ({ page }) => {
  await withOperatorKey(page);
  await page.goto("/");
  await logIn(page);
  await expect(page.locator("tr[aria-selected='true']")).toHaveCount(1);

  // j déplace la sélection ; r ouvre le rejet de la demande sélectionnée.
  const first = await page.locator("tr[aria-selected='true']").getAttribute("data-testid");
  await page.keyboard.press("j");
  const second = await page.locator("tr[aria-selected='true']").getAttribute("data-testid");
  expect(second).not.toBe(first);
  const tx = second!.replace("row-", "");
  await page.keyboard.press("r");

  // Sans motif, rien ne part.
  await page.getByTestId("comment-next").click();
  await expect(page.getByTestId("comment-dialog")).toBeVisible();
  await page.getByTestId("comment").fill("sujet non reconnu");
  await page.getByTestId("comment-next").click();
  await expect(page.getByTestId("frozen-body")).toContainText(`"action": "reject_request"`);
  await page.getByTestId("sign").click();
  await expect(page.getByTestId("sign-dialog")).toBeHidden();
  expect(await stateOf(page, tx)).toMatchObject({ state: "REJECTED" });
});

test("renoncer avant de signer ne décide rien", async ({ page }) => {
  await withOperatorKey(page);
  await page.goto("/");
  await logIn(page);
  const tx = fixture().pending[5]!;
  await page.getByTestId(`row-${tx}`).click();
  await page.getByTestId("approve").click();
  await page.getByTestId("comment-next").click();
  await expect(page.getByTestId("frozen-body")).toContainText(tx);
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("sign-dialog")).toBeHidden();
  expect(await stateOf(page, tx)).toMatchObject({ state: "PENDING" });
});
