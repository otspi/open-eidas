// Cérémonie de signature d'une action (docs/UI-UX.md §3.1, docs/WEBUI.md §4).
//
// 1. La console demande à ca-server de figer l'action : le corps rendu est
//    celui qui sera exécuté, affiché tel quel, avec son empreinte SHA-256.
// 2. L'opérateur signe avec sa clé FIDO2.
// 3. L'assertion est relayée ; en cas d'erreur, la modale reste ouverte et
//    l'opérateur peut relancer sans ressaisir.
//
// La modale est un <dialog> natif : focus piégé, Échap ferme — sauf pendant la
// cérémonie matérielle — et un clic extérieur ne la ferme jamais (§5.2).

import { call, isError } from "./api";
import { h, replace } from "./dom";
import { groupedHash } from "./format";
import { assert } from "./webauthn";

interface Issued {
  challenge_id: string;
  body: Record<string, unknown>;
  body_hash: string;
  webauthn: Parameters<typeof assert>[0];
}

export interface Signing {
  /// Titre de la modale (« Approbation de la demande tx-… »).
  title: string;
  /// Résumé en clair, ligne par ligne, de ce qui va être signé.
  summary: [string, string][];
  /// L'action à figer (forme d'oe_actions).
  action: Record<string, unknown>;
  /// La route qui relaie l'assertion (ex. /api/v1/requests/{id}/approve).
  route: string;
}

const MESSAGES: Record<string, string> = {
  action_mismatch: "La signature ne correspond pas à cette action.",
  already_used: "Cette signature a déjà servi : relancez.",
  expired: "Le délai de signature est dépassé : relancez.",
  denied: "Action refusée par l'autorité (rôle ou état de la demande).",
  signature_rejected: "Signature refusée par l'autorité.",
  unauthenticated: "Session expirée : reconnectez-vous.",
};

function explain(body: unknown, fallback: string): string {
  if (isError(body)) return MESSAGES[body.error] ?? body.message;
  return fallback;
}

/// Ouvre la modale ; rend la réponse de l'autorité si l'action a été signée et
/// relayée avec succès, `null` sinon.
export function sign(signing: Signing): Promise<Record<string, unknown> | null> {
  return new Promise((resolve) => {
    let busy = false;
    let done = false;
    let issued: Issued | null = null;

    const status = h("p", { class: "status", role: "status", "aria-live": "polite", "data-testid": "sign-status" });
    const frozen = h("div", { class: "frozen", "data-testid": "frozen" });
    const signButton = h("button", { type: "button", class: "primary", "data-testid": "sign" }, "Signer avec ma clé FIDO2");
    const cancel = h("button", { type: "button", "data-testid": "sign-cancel" }, "Annuler");
    const summary = h(
      "dl",
      { class: "summary" },
      ...signing.summary.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]),
    );
    const dialog = h(
      "dialog",
      { class: "signature", "aria-labelledby": "sign-title", "data-testid": "sign-dialog" },
      h("h2", { id: "sign-title" }, `🔑 ${signing.title}`),
      summary,
      frozen,
      status,
      h("div", { class: "actions" }, cancel, signButton),
    );

    const close = (result: Record<string, unknown> | null): void => {
      dialog.close();
      dialog.remove();
      resolve(result);
    };

    const prepare = async (): Promise<boolean> => {
      signButton.disabled = true;
      status.textContent = "Préparation de l'action par l'autorité…";
      const reply = await call<Issued>("POST", "/api/v1/webauthn/challenge", signing.action);
      if (reply.status !== 200 || reply.body === null || isError(reply.body)) {
        status.textContent = explain(reply.body, "L'autorité n'a pas pu préparer l'action.");
        return false;
      }
      issued = reply.body;
      replace(
        frozen,
        h("p", { class: "muted" }, "Corps exact qui sera exécuté (figé par l'autorité) :"),
        h("pre", { class: "mono", "data-testid": "frozen-body" }, JSON.stringify(issued.body, null, 2)),
        h("p", { class: "muted" }, "Empreinte de la requête (SHA-256) :"),
        h("p", { class: "mono hash", "data-testid": "body-hash" }, groupedHash(issued.body_hash)),
      );
      status.textContent = "";
      signButton.disabled = false;
      return true;
    };

    const ceremony = async (): Promise<void> => {
      if (issued === null && !(await prepare())) return;
      const current = issued;
      if (current === null) return;
      busy = true;
      signButton.disabled = true;
      cancel.disabled = true;
      status.textContent = "Touchez votre clé de sécurité matérielle…";
      try {
        const assertion = await assert(current.webauthn);
        const reply = await call<Record<string, unknown>>("POST", signing.route, {
          challenge_id: current.challenge_id,
          assertion,
        });
        if (reply.status === 200 && reply.body !== null && !isError(reply.body)) {
          done = true;
          const result = reply.body;
          status.textContent =
            result.status === "AWAITING_QUORUM" ? "✓ Signature enregistrée." : "✓ Action signée et exécutée.";
          window.setTimeout(() => close(result), 800);
          return;
        }
        // Un challenge consommé ou expiré ne resservira pas : on en redemande un.
        issued = null;
        status.textContent = explain(reply.body, "L'autorité a refusé l'action.");
      } catch {
        status.textContent = "La clé n'a pas répondu (annulation ou délai). Réessayez.";
      } finally {
        busy = false;
        if (!done) {
          signButton.disabled = false;
          cancel.disabled = false;
        }
      }
    };

    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      if (!busy && !done) close(null);
    });
    cancel.addEventListener("click", () => {
      if (!busy) close(null);
    });
    signButton.addEventListener("click", () => void ceremony());

    document.body.append(dialog);
    dialog.showModal();
    void prepare().then(() => signButton.focus());
  });
}
