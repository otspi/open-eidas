// Aides communes aux parcours Playwright : la fixture écrite par
// examples/e2e_console.rs, la clé de l'opérateur confiée à l'authentificateur
// WebAuthn virtuel, la connexion.

import { expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fixturePath } from "../playwright.config";

type Credential = Record<string, unknown> & { signCount: number };

export interface Fixture {
  operator: string;
  pending: string[];
  certificates: string[];
  credential: Credential;
  operators: Record<string, { role: string; credential: Credential }>;
}

export const fixture = (): Fixture => JSON.parse(readFileSync(fixturePath, "utf8")) as Fixture;

// Chaque test recrée un authentificateur : son compteur doit dépasser ceux
// déjà vus par la console et par ca-server, sans quoi ils détectent (à juste
// titre) un clone. Module partagé : le compteur croît d'un fichier à l'autre.
let signCountBase = 1000;

export async function withOperatorKey(page: Page, who?: string): Promise<void> {
  const credential = who === undefined ? fixture().credential : fixture().operators[who]!.credential;
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
    credential: { ...credential, signCount: credential.signCount + signCountBase },
  } as never);
}

/// Exceptions de la page et violations de CSP : aucune n'est admise. Les
/// réponses d'erreur HTTP attendues (401 avant connexion) n'en sont pas.
export function collectErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(e.message));
  return errors;
}

export async function logIn(page: Page, who: string = fixture().operator): Promise<void> {
  await page.getByTestId("login-name").fill(who);
  await page.getByTestId("login-submit").click();
  await expect(page.getByTestId("operator")).toHaveText(who);
}
