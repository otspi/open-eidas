// Révocation à deux dans le navigateur (docs/WEBUI.md §8, §15 étape 6c,
// docs/UI-UX.md §3.2) : bob signe la révocation, rien n'est révoqué ; il ne
// peut pas co-signer lui-même ; carol co-signe, ca-server exécute.

import { expect, test, type Page } from "@playwright/test";
import { collectErrors, fixture, logIn, withOperatorKey } from "./helpers";

async function statusOf(page: Page, serial: string): Promise<string | undefined> {
  for (const status of ["issued", "revoked"]) {
    const list = (await (await page.request.get(`/api/v1/certificates?status=${status}`)).json()) as {
      serial_hex: string;
    }[];
    if (list.some((c) => c.serial_hex === serial)) return status;
  }
  return undefined;
}

test("deux opérateurs CA distincts révoquent un certificat", async ({ browser }) => {
  const serial = fixture().certificates[0]!;

  // bob : première signature.
  const bobContext = await browser.newContext();
  const bob = await bobContext.newPage();
  const errors = collectErrors(bob);
  await withOperatorKey(bob, "bob");
  await bob.goto("/");
  await logIn(bob, "bob");
  await bob.getByTestId("nav-certificates").click();
  await bob.getByTestId(`cert-${serial}`).click();
  await bob.getByTestId("revoke").click();
  await bob.getByTestId("reason").selectOption("1");
  await bob.getByTestId("comment").fill("clé exposée, ticket CERT-FR #2026-991");
  await bob.getByTestId("comment-next").click();
  const body = bob.getByTestId("frozen-body");
  await expect(body).toContainText(`"serial": "${serial}"`);
  await expect(body).toContainText(`"reason": 1`);
  await bob.getByTestId("sign").click();
  await expect(bob.getByTestId("sign-dialog")).toBeHidden();
  await expect(bob.getByTestId("certificates-status")).toContainText("1 sur 2");
  expect(await statusOf(bob, serial)).toBe("issued");

  // bob ne peut pas co-signer sa propre action.
  await bob.getByTestId("nav-quorum").click();
  const card = bob.locator("article", { hasText: serial.toUpperCase().match(/.{2}/g)!.join(":") });
  await expect(card).toContainText("1 sur 2");
  await expect(card.getByRole("button", { name: /Co-signer/ })).toBeDisabled();
  await expect(card).toContainText("opérateur distinct");
  expect(errors).toEqual([]);

  // carol co-signe : la révocation s'exécute.
  const carolContext = await browser.newContext();
  const carol = await carolContext.newPage();
  await withOperatorKey(carol, "carol");
  await carol.goto("/");
  await logIn(carol, "carol");
  await expect(carol.getByTestId("count-quorum")).toHaveText("(1)");
  await carol.getByTestId("nav-quorum").click();
  const pending = carol.locator("article", { hasText: "bob" });
  await pending.getByRole("button", { name: /Co-signer/ }).click();
  await expect(carol.getByTestId("frozen-body")).toContainText(`"serial": "${serial}"`);
  await carol.getByTestId("sign").click();
  await expect(carol.getByTestId("sign-dialog")).toBeHidden();
  await expect(carol.getByTestId("quorum-status")).toContainText("exécutée");
  expect(await statusOf(carol, serial)).toBe("revoked");
  await expect(carol.getByTestId("count-quorum")).toHaveText("(0)");

  await bobContext.close();
  await carolContext.close();
});

test("un opérateur RA ne peut pas lancer de révocation", async ({ page }) => {
  const serial = fixture().certificates[1]!;
  await withOperatorKey(page);
  await page.goto("/");
  await logIn(page);
  await page.getByTestId("nav-certificates").click();
  await page.getByTestId(`cert-${serial}`).click();
  await page.getByTestId("revoke").click();
  await page.getByTestId("reason").selectOption("4");
  await page.getByTestId("comment").fill("essai");
  await page.getByTestId("comment-next").click();
  // L'autorité refuse de préparer l'action : la modale le dit, rien n'est figé.
  await expect(page.getByTestId("sign-status")).toContainText("refusée");
  await expect(page.getByTestId("frozen-body")).toHaveCount(0);
  await page.keyboard.press("Escape");
  expect(await statusOf(page, serial)).toBe("issued");
});
