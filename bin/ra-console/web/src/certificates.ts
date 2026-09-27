// Certificats émis et révocation (docs/UI-UX.md §3.1, §4.2, §5 ; docs/WEBUI.md
// §8) : la révocation exige deux ca_operateur distincts, la première signature
// part en salle de quorum.

import { call, isError } from "./api";
import { h, replace } from "./dom";
import { utc } from "./format";
import { sign } from "./sign";
import type { View } from "./view";

interface Certificate {
  serial_hex: string;
  profile: string;
  subject_dn: string;
  not_after: string | null;
  status: string;
}

/// Motifs admis par ca-server (RFC 5280 §5.3.1) ; « unspecified » n'en fait pas partie.
const REASONS: [number, string][] = [
  [1, "keyCompromise — clé privée compromise"],
  [3, "affiliationChanged — rattachement modifié"],
  [4, "superseded — remplacé"],
  [5, "cessationOfOperation — cessation d'activité"],
  [9, "privilegeWithdrawn — privilège retiré"],
];

/// Numéro de série par paires séparées par deux-points (UI-UX §4.2).
export function pairs(hex: string): string {
  return (hex.toUpperCase().match(/.{1,2}/g) ?? []).join(":");
}

export function certificatesView(onSigned: () => void): View {
  let rows: Certificate[] = [];
  let selected = 0;
  const body = h("tbody", {});
  const notice = h("p", { class: "status", role: "status", "aria-live": "polite", "data-testid": "certificates-status" });
  const inspector = h("aside", { class: "inspector", "aria-label": "Inspecteur" });
  const element = h(
    "section",
    {},
    h("h1", {}, "Certificats émis"),
    notice,
    h(
      "div",
      { class: "split" },
      h(
        "table",
        { class: "dense", "data-testid": "certificates" },
        h("thead", {}, h("tr", {}, h("th", {}, "Statut"), h("th", {}, "Numéro de série"), h("th", {}, "Sujet"), h("th", {}, "Profil"), h("th", {}, "Expire le"))),
        body,
      ),
      inspector,
    ),
  );

  const render = (): void => {
    replace(
      body,
      ...rows.map((c, i) => {
        const tr = h(
          "tr",
          { "aria-selected": String(i === selected), "data-testid": `cert-${c.serial_hex}` },
          h("td", {}, h("span", { class: "badge valid" }, "● actif")),
          h("td", { class: "mono" }, pairs(c.serial_hex)),
          h("td", {}, c.subject_dn),
          h("td", {}, c.profile),
          h("td", { class: "mono" }, c.not_after ? utc(c.not_after) : "—"),
        );
        tr.addEventListener("click", () => {
          selected = i;
          render();
        });
        return tr;
      }),
    );
    const c = rows[selected];
    if (c === undefined) {
      replace(inspector, h("p", { class: "muted" }, "Aucun certificat actif."));
      return;
    }
    const revoke = h("button", { type: "button", class: "danger", "data-testid": "revoke" }, "Révoquer le certificat…");
    revoke.addEventListener("click", () => void startRevocation(c));
    replace(
      inspector,
      h("h2", {}, "Général"),
      h(
        "dl",
        {},
        h("dt", {}, "Numéro de série"),
        h("dd", { class: "mono" }, pairs(c.serial_hex)),
        h("dt", {}, "Sujet"),
        h("dd", {}, c.subject_dn),
        h("dt", {}, "Profil"),
        h("dd", {}, c.profile),
        h("dt", {}, "Expire le"),
        h("dd", { class: "mono" }, c.not_after ? utc(c.not_after) : "—"),
      ),
      h("p", { class: "muted" }, "La révocation exige la signature de deux opérateurs CA distincts."),
      h("div", { class: "actions" }, revoke),
    );
  };

  const startRevocation = async (c: Certificate): Promise<void> => {
    const choice = await askRevocation();
    if (choice === null) return;
    const [code, label] = REASONS.find(([r]) => r === choice.reason) ?? [choice.reason, String(choice.reason)];
    const result = await sign({
      title: "Révocation de certificat",
      summary: [
        ["Action", "révoquer définitivement le certificat"],
        ["Numéro de série", pairs(c.serial_hex)],
        ["Sujet", c.subject_dn],
        ["Motif RFC 5280", `${label} (${code})`],
        ["Justification", choice.comment],
      ],
      action: { action: "revoke_certificate", serial: c.serial_hex, reason: choice.reason, comment: choice.comment },
      route: `/api/v1/certificates/${c.serial_hex}/revoke`,
    });
    if (result === null) return;
    notice.textContent =
      result.status === "AWAITING_QUORUM"
        ? `Signature enregistrée (${String(result.signatures)} sur ${String(result.required)}) : en attente d'un second opérateur CA, voir la salle de quorum.`
        : `Certificat ${pairs(c.serial_hex)} révoqué.`;
    await load();
    onSigned();
  };

  const load = async (): Promise<void> => {
    const reply = await call<Certificate[]>("GET", "/api/v1/certificates?status=issued");
    rows = Array.isArray(reply.body) ? reply.body : [];
    if (isError(reply.body)) notice.textContent = reply.body.message;
    selected = Math.min(selected, Math.max(rows.length - 1, 0));
    render();
  };

  void load();
  return { element, dispose: () => undefined };
}

function askRevocation(): Promise<{ reason: number; comment: string } | null> {
  return new Promise((resolve) => {
    const reason = h(
      "select",
      { id: "revocation-reason", required: "", "data-testid": "reason" },
      h("option", { value: "" }, "— choisir un motif —"),
      ...REASONS.map(([code, label]) => h("option", { value: String(code) }, label)),
    );
    const comment = h("textarea", { id: "revocation-comment", rows: "3", maxlength: "1000", required: "", "data-testid": "comment" });
    const next = h("button", { type: "submit", class: "danger", "data-testid": "comment-next" }, "Préparer la signature");
    const cancel = h("button", { type: "button" }, "Annuler");
    const form = h(
      "form",
      { method: "dialog" },
      h("h2", {}, "Révocation : motif et justification"),
      h("label", { for: "revocation-reason" }, "Motif (RFC 5280)"),
      reason,
      h("label", { for: "revocation-comment" }, "Justification consignée au journal (obligatoire)"),
      comment,
      h("div", { class: "actions" }, cancel, next),
    );
    const dialog = h("dialog", { class: "signature", "data-testid": "revocation-dialog" }, form);
    const finish = (value: { reason: number; comment: string } | null): void => {
      dialog.close();
      dialog.remove();
      resolve(value);
    };
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const code = Number(reason.value);
      const text = comment.value.trim();
      if (!REASONS.some(([r]) => r === code) || text === "") return;
      finish({ reason: code, comment: text });
    });
    cancel.addEventListener("click", () => finish(null));
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      finish(null);
    });
    document.body.append(dialog);
    dialog.showModal();
    reason.focus();
  });
}
