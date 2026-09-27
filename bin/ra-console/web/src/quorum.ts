// Salle d'attente du double contrôle (docs/UI-UX.md §3.2, docs/WEBUI.md §8) :
// ce qui attend une signature de plus, qui a déjà signé, et la co-signature —
// refusée d'avance à qui a déjà signé (l'autorité la refuserait de toute façon).

import { call, isError, type Me } from "./api";
import { pairs } from "./certificates";
import { h, replace } from "./dom";
import { groupedHash, utc } from "./format";
import { sign } from "./sign";
import type { View } from "./view";

interface Pending {
  action_id: string;
  action: string;
  body: Record<string, unknown>;
  body_hash: string;
  required: number;
  signatures: number;
  signed_by: string[];
  created_at: string;
  expires_at: string;
}

const LABELS: Record<string, string> = {
  revoke_certificate: "Révocation de certificat",
  set_role: "Changement de rôle",
  invite_operator: "Invitation d'un opérateur",
};

export function quorumView(me: Me, onSigned: () => void): View {
  const list = h("div", { class: "quorum", "data-testid": "quorum" });
  const notice = h("p", { class: "status", role: "status", "aria-live": "polite", "data-testid": "quorum-status" });
  const element = h("section", {}, h("h1", {}, "Salle de quorum"), notice, list);

  const card = (p: Pending): HTMLElement => {
    const mine = p.signed_by.includes(me.operator);
    const cosign = h(
      "button",
      { type: "button", class: "primary", "data-testid": `cosign-${p.action_id}`, ...(mine ? { disabled: "" } : {}) },
      "Co-signer avec ma clé FIDO2",
    );
    cosign.addEventListener("click", () => void coSign(p));
    const serial = typeof p.body.serial === "string" ? p.body.serial : null;
    return h(
      "article",
      { class: "card", "data-testid": `pending-${p.action_id}` },
      h("h2", {}, LABELS[p.action] ?? p.action),
      h(
        "dl",
        {},
        h("dt", {}, "Signatures"),
        h("dd", { "data-testid": `progress-${p.action_id}` }, `${p.signatures} sur ${p.required}`),
        h("dt", {}, "Déjà signé par"),
        h("dd", {}, p.signed_by.join(", ") || "—"),
        ...(serial ? [h("dt", {}, "Numéro de série"), h("dd", { class: "mono" }, pairs(serial))] : []),
        h("dt", {}, "Initiée le"),
        h("dd", { class: "mono" }, utc(p.created_at)),
        h("dt", {}, "Expire le"),
        h("dd", { class: "mono" }, utc(p.expires_at)),
        h("dt", {}, "Empreinte"),
        h("dd", { class: "mono hash" }, groupedHash(p.body_hash)),
      ),
      h("pre", { class: "mono" }, JSON.stringify(p.body, null, 2)),
      mine ? h("p", { class: "muted", "data-testid": `own-${p.action_id}` }, "Le double contrôle requiert un opérateur distinct : vous avez déjà signé.") : null,
      h("div", { class: "actions" }, cosign),
    );
  };

  const coSign = async (p: Pending): Promise<void> => {
    const result = await sign({
      title: `Co-signature : ${LABELS[p.action] ?? p.action}`,
      summary: [
        ["Action", LABELS[p.action] ?? p.action],
        ["Déjà signé par", p.signed_by.join(", ")],
        ["Signatures", `${p.signatures + 1} sur ${p.required} après la vôtre`],
      ],
      action: { action_id: p.action_id },
      route: `/api/v1/quorum/${p.action_id}/sign`,
    });
    if (result === null) return;
    notice.textContent = result.status === "EXECUTED" ? "Action exécutée par l'autorité." : "Signature enregistrée.";
    await load();
    onSigned();
  };

  const load = async (): Promise<void> => {
    const reply = await call<Pending[]>("GET", "/api/v1/quorum?state=PENDING");
    const pending = Array.isArray(reply.body) ? reply.body : [];
    if (isError(reply.body)) notice.textContent = reply.body.message;
    replace(list, ...(pending.length === 0 ? [h("p", { class: "muted" }, "Aucune action en attente de signature.")] : pending.map(card)));
  };

  void load();
  return { element, dispose: () => undefined };
}
