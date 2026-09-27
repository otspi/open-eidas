// Registre des opérateurs dans le navigateur (docs/WEBUI.md §10, §15 étape
// 6e) : invitation (jeton affiché une seule fois), changement de rôle,
// révocation de clé — chaque écriture signée et exécutée par ca-server.

import { expect, test, type Page } from "@playwright/test";
import { collectErrors, logIn, withOperatorKey } from "./helpers";

interface Registry {
  operators: { name: string; role: string; credentials: { revoked_at: string | null }[] }[];
}

async function registry(page: Page): Promise<Registry> {
  return (await (await page.request.get("/api/v1/operators")).json()) as Registry;
}

test("un administrateur invite, change un rôle et révoque une clé", async ({ page }) => {
  const errors = collectErrors(page);
  await withOperatorKey(page, "root");
  await page.goto("/");
  await logIn(page, "root");
  await page.getByTestId("nav-operators").click();

  // Invitation : le jeton n'est montré qu'une fois.
  await page.getByTestId("invite").click();
  await page.getByTestId("invite-name").fill("frank");
  await page.getByTestId("invite-role").selectOption("ra_operateur");
  await page.getByTestId("comment-next").click();
  await expect(page.getByTestId("frozen-body")).toContainText(`"action": "invite_operator"`);
  await page.getByTestId("sign").click();
  const token = page.getByTestId("invite-token");
  await expect(token).toHaveText(/^\S{30,}$/);
  await page.getByTestId("token-close").click();
  await expect(page.getByTestId("token-dialog")).toHaveCount(0);
  await expect(page.getByTestId("operator-frank")).toBeVisible();

  // Rôle de dave : auditeur (pas de double contrôle hors rôle admin).
  await page.getByTestId("operator-dave").click();
  await page.getByTestId("new-role").selectOption("auditeur");
  await page.getByTestId("change-role").click();
  await expect(page.getByTestId("frozen-body")).toContainText(`"operator": "dave"`);
  await page.getByTestId("sign").click();
  await expect(page.getByTestId("operators-status")).toContainText("auditeur");
  expect((await registry(page)).operators.find((o) => o.name === "dave")?.role).toBe("auditeur");

  // Révocation de la clé de dave, motif obligatoire.
  await page.getByTestId("operator-dave").click();
  await page.getByTestId("revoke-key-dave").click();
  await page.getByTestId("comment").fill("départ de l'association");
  await page.getByTestId("comment-next").click();
  await expect(page.getByTestId("frozen-body")).toContainText(`"action": "revoke_key"`);
  await page.getByTestId("sign").click();
  await expect(page.getByTestId("operators-status")).toContainText("révoquée");
  const dave = (await registry(page)).operators.find((o) => o.name === "dave");
  expect(dave?.credentials.every((c) => c.revoked_at !== null)).toBe(true);
  expect(errors).toEqual([]);
});

test("un non-administrateur consulte le registre sans pouvoir l'écrire", async ({ page }) => {
  await withOperatorKey(page);
  await page.goto("/");
  await logIn(page);
  await page.getByTestId("nav-operators").click();
  await expect(page.getByTestId("operator-root")).toBeVisible();
  await expect(page.getByTestId("invite")).toBeDisabled();
  await page.getByTestId("operator-root").click();
  await expect(page.getByTestId("change-role")).toBeDisabled();
  await expect(page.getByTestId("revoke-key-root")).toBeDisabled();
});
