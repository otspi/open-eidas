// Écran de connexion (docs/WEBUI.md §15 étape 1c) : le nom de l'opérateur,
// puis sa clé FIDO2. Les refus ont tous la même forme (§16) : l'écran ne
// distingue jamais un nom inconnu d'une clé refusée.

import { call, isError, type ConsoleInfo, type Me } from "./api";
import { banner } from "./banner";
import { h, replace } from "./dom";
import { assert } from "./webauthn";

interface Begun {
  challenge_id: string;
  webauthn: Parameters<typeof assert>[0];
}

export function renderLogin(root: HTMLElement, info: ConsoleInfo, onLoggedIn: (me: Me) => void, notice?: string): void {
  const status = h("p", { class: "status", role: "status", "aria-live": "polite", "data-testid": "login-status" }, notice ?? "");
  const name = h("input", {
    id: "operator-name",
    name: "operator",
    autocomplete: "username webauthn",
    required: "",
    maxlength: "256",
    "data-testid": "login-name",
  });
  const submit = h("button", { type: "submit", class: "primary", "data-testid": "login-submit" }, "Se connecter avec ma clé FIDO2");
  const form = h(
    "form",
    { class: "login-form", "aria-labelledby": "login-title" },
    h("h1", { id: "login-title" }, "Console d'opération Open eIDAS"),
    h("label", { for: "operator-name" }, "Nom d'opérateur"),
    name,
    submit,
    status,
  );
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void login(name.value.trim(), submit, status, onLoggedIn);
  });
  replace(root, banner(info), h("main", { class: "login" }, form));
  name.focus();
}

async function login(name: string, submit: HTMLButtonElement, status: HTMLElement, onLoggedIn: (me: Me) => void): Promise<void> {
  if (name === "") return;
  submit.disabled = true;
  status.textContent = "Touchez votre clé de sécurité matérielle…";
  try {
    const begun = await call<Begun>("POST", "/api/v1/webauthn/login/begin", { name });
    if (begun.status !== 200 || begun.body === null || isError(begun.body)) {
      status.textContent = "Connexion impossible pour le moment.";
      return;
    }
    const credential = await assert(begun.body.webauthn);
    const done = await call<Me>("POST", "/api/v1/webauthn/login/finish", {
      challenge_id: begun.body.challenge_id,
      credential,
    });
    if (done.status !== 200 || done.body === null || isError(done.body)) {
      status.textContent = "Identifiants invalides.";
      return;
    }
    onLoggedIn(done.body);
  } catch {
    // Annulation, délai dépassé, clé inconnue du navigateur : une seule forme.
    status.textContent = "La clé n'a pas répondu. Réessayez.";
  } finally {
    submit.disabled = false;
  }
}
