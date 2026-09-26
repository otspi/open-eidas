# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: operators.spec.ts >> un non-administrateur consulte le registre sans pouvoir l'écrire
- Location: e2e/operators.spec.ts:58:1

# Error details

```
Error: expect(locator).toBeDisabled() failed

Locator:  getByTestId('invite')
Expected: disabled
Received: enabled
Timeout:  5000ms

Call log:
  - Expect "toBeDisabled" getByTestId('invite') with timeout 5000ms
  - waiting for getByTestId('invite')
    14 × locator resolved to <button type="button" class="primary" data-testid="invite">Inviter un opérateur…</button>
       - unexpected value "enabled"

```

```yaml
- button "Inviter un opérateur…"
```

# Test source

```ts
  1  | // Registre des opérateurs dans le navigateur (docs/WEBUI.md §10, §15 étape
  2  | // 6e) : invitation (jeton affiché une seule fois), changement de rôle,
  3  | // révocation de clé — chaque écriture signée et exécutée par ca-server.
  4  | 
  5  | import { expect, test, type Page } from "@playwright/test";
  6  | import { collectErrors, logIn, withOperatorKey } from "./helpers";
  7  | 
  8  | interface Registry {
  9  |   operators: { name: string; role: string; credentials: { revoked_at: string | null }[] }[];
  10 | }
  11 | 
  12 | async function registry(page: Page): Promise<Registry> {
  13 |   return (await (await page.request.get("/api/v1/operators")).json()) as Registry;
  14 | }
  15 | 
  16 | test("un administrateur invite, change un rôle et révoque une clé", async ({ page }) => {
  17 |   const errors = collectErrors(page);
  18 |   await withOperatorKey(page, "root");
  19 |   await page.goto("/");
  20 |   await logIn(page, "root");
  21 |   await page.getByTestId("nav-operators").click();
  22 | 
  23 |   // Invitation : le jeton n'est montré qu'une fois.
  24 |   await page.getByTestId("invite").click();
  25 |   await page.getByTestId("invite-name").fill("frank");
  26 |   await page.getByTestId("invite-role").selectOption("ra_operateur");
  27 |   await page.getByTestId("comment-next").click();
  28 |   await expect(page.getByTestId("frozen-body")).toContainText(`"action": "invite_operator"`);
  29 |   await page.getByTestId("sign").click();
  30 |   const token = page.getByTestId("invite-token");
  31 |   await expect(token).toHaveText(/^\S{30,}$/);
  32 |   await page.getByTestId("token-close").click();
  33 |   await expect(page.getByTestId("token-dialog")).toHaveCount(0);
  34 |   await expect(page.getByTestId("operator-frank")).toBeVisible();
  35 | 
  36 |   // Rôle de dave : auditeur (pas de double contrôle hors rôle admin).
  37 |   await page.getByTestId("operator-dave").click();
  38 |   await page.getByTestId("new-role").selectOption("auditeur");
  39 |   await page.getByTestId("change-role").click();
  40 |   await expect(page.getByTestId("frozen-body")).toContainText(`"operator": "dave"`);
  41 |   await page.getByTestId("sign").click();
  42 |   await expect(page.getByTestId("operators-status")).toContainText("auditeur");
  43 |   expect((await registry(page)).operators.find((o) => o.name === "dave")?.role).toBe("auditeur");
  44 | 
  45 |   // Révocation de la clé de dave, motif obligatoire.
  46 |   await page.getByTestId("operator-dave").click();
  47 |   await page.getByTestId("revoke-key-dave").click();
  48 |   await page.getByTestId("comment").fill("départ de l'association");
  49 |   await page.getByTestId("comment-next").click();
  50 |   await expect(page.getByTestId("frozen-body")).toContainText(`"action": "revoke_key"`);
  51 |   await page.getByTestId("sign").click();
  52 |   await expect(page.getByTestId("operators-status")).toContainText("révoquée");
  53 |   const dave = (await registry(page)).operators.find((o) => o.name === "dave");
  54 |   expect(dave?.credentials.every((c) => c.revoked_at !== null)).toBe(true);
  55 |   expect(errors).toEqual([]);
  56 | });
  57 | 
  58 | test("un non-administrateur consulte le registre sans pouvoir l'écrire", async ({ page }) => {
  59 |   await withOperatorKey(page);
  60 |   await page.goto("/");
  61 |   await logIn(page);
  62 |   await page.getByTestId("nav-operators").click();
  63 |   await expect(page.getByTestId("operator-root")).toBeVisible();
> 64 |   await expect(page.getByTestId("invite")).toBeDisabled();
     |                                            ^ Error: expect(locator).toBeDisabled() failed
  65 |   await page.getByTestId("operator-root").click();
  66 |   await expect(page.getByTestId("change-role")).toBeDisabled();
  67 |   await expect(page.getByTestId("revoke-key-root")).toBeDisabled();
  68 | });
  69 | 
```