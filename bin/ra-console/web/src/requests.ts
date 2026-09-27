// File des demandes d'enrôlement (docs/UI-UX.md §3.4, §5.1, §6.1) : tableau
// dense, sélection au clavier (j/k), inspecteur latéral, décisions signées.

import { call, isError } from "./api";
import { h, replace } from "./dom";
import { utc } from "./format";
import { sign } from "./sign";

interface EnrollmentRequest {
  transaction_id: string;
  profile: string;
  subject_cn: string;
  state: string;
  operator: string | null;
  created_at: string;
}

export interface RequestsView {
  element: HTMLElement;
  /// Retire les raccourcis clavier quand la vue est quittée.
  dispose: () => void;
}

export function requestsView(onDecided: () => void): RequestsView {
  let rows: EnrollmentRequest[] = [];
  let selected = 0;

  const body = h("tbody", {});
  const table = h(
    "table",
    { class: "dense", "aria-label": "Demandes en attente", "data-testid": "requests" },
    h(
      "thead",
      {},
      h("tr", {}, h("th", {}, "Statut"), h("th", {}, "Transaction"), h("th", {}, "Sujet"), h("th", {}, "Profil"), h("th", {}, "Déposée le")),
    ),
    body,
  );
  const inspector = h("aside", { class: "inspector", "aria-label": "Inspecteur", "data-testid": "inspector" });
  const notice = h("p", { class: "status", role: "status", "aria-live": "polite", "data-testid": "requests-status" });
  const element = h(
    "section",
    { class: "requests" },
    h("h1", {}, "Demandes d'enrôlement en attente"),
    h("p", { class: "muted" }, "j/k : se déplacer · a : approuver · r : rejeter"),
    notice,
    h("div", { class: "split" }, table, inspector),
  );

  const render = (): void => {
    replace(
      body,
      ...rows.map((r, i) => {
        const tr = h(
          "tr",
          { "aria-selected": String(i === selected), "data-testid": `row-${r.transaction_id}` },
          h("td", {}, h("span", { class: "badge pending" }, "⏳ en attente")),
          h("td", { class: "mono" }, r.transaction_id),
          h("td", {}, r.subject_cn),
          h("td", {}, r.profile),
          h("td", { class: "mono" }, utc(r.created_at)),
        );
        tr.addEventListener("click", () => {
          selected = i;
          render();
        });
        return tr;
      }),
    );
    if (rows.length === 0) {
      replace(body, h("tr", {}, h("td", { colspan: "5", class: "muted" }, "Aucune demande en attente.")));
    }
    renderInspector();
  };

  const renderInspector = (): void => {
    const r = rows[selected];
    if (r === undefined) {
      replace(inspector, h("p", { class: "muted" }, "Aucune demande sélectionnée."));
      return;
    }
    const approve = h("button", { type: "button", class: "primary", "data-testid": "approve" }, "Approuver la demande…");
    const reject = h("button", { type: "button", "data-testid": "reject" }, "Rejeter la demande…");
    approve.addEventListener("click", () => void decide(r, "approve"));
    reject.addEventListener("click", () => void decide(r, "reject"));
    replace(
      inspector,
      h("h2", {}, "Général"),
      h(
        "dl",
        {},
        h("dt", {}, "Transaction"),
        h("dd", { class: "mono" }, r.transaction_id),
        h("dt", {}, "Sujet (CN)"),
        h("dd", {}, r.subject_cn),
        h("dt", {}, "Profil"),
        h("dd", {}, r.profile),
        h("dt", {}, "Déposée le"),
        h("dd", { class: "mono" }, utc(r.created_at)),
      ),
      h("div", { class: "actions" }, approve, reject),
    );
  };

  const decide = async (r: EnrollmentRequest, kind: "approve" | "reject"): Promise<void> => {
    const comment = await askComment(kind);
    if (comment === null) return;
    const approving = kind === "approve";
    const ok = await sign({
      title: approving ? `Approbation de la demande ${r.transaction_id}` : `Rejet de la demande ${r.transaction_id}`,
      summary: [
        ["Action", approving ? "approuver l'émission du certificat" : "rejeter définitivement la demande"],
        ["Transaction", r.transaction_id],
        ["Sujet (CN)", r.subject_cn],
        ["Profil", r.profile],
        ["Justification", comment === "" ? "—" : comment],
      ],
      action: {
        action: approving ? "approve_request" : "reject_request",
        transaction_id: r.transaction_id,
        comment,
      },
      route: `/api/v1/requests/${encodeURIComponent(r.transaction_id)}/${kind}`,
    });
    if (ok) {
      notice.textContent = approving ? `Demande ${r.transaction_id} approuvée.` : `Demande ${r.transaction_id} rejetée.`;
      await load();
      onDecided();
    }
  };

  const load = async (): Promise<void> => {
    const reply = await call<EnrollmentRequest[]>("GET", "/api/v1/requests?state=PENDING");
    if (reply.status !== 200 || !Array.isArray(reply.body)) {
      notice.textContent = isError(reply.body) ? reply.body.message : "File indisponible.";
      rows = [];
    } else {
      rows = reply.body;
    }
    selected = Math.min(selected, Math.max(rows.length - 1, 0));
    render();
  };

  const onKey = (event: KeyboardEvent): void => {
    const target = event.target as HTMLElement | null;
    if (document.querySelector("dialog[open]") !== null) return;
    if (target !== null && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return;
    const r = rows[selected];
    if (event.key === "j" || event.key === "ArrowDown") {
      selected = Math.min(selected + 1, rows.length - 1);
      render();
    } else if (event.key === "k" || event.key === "ArrowUp") {
      selected = Math.max(selected - 1, 0);
      render();
    } else if (event.key === "a" && r !== undefined) {
      void decide(r, "approve");
    } else if (event.key === "r" && r !== undefined) {
      void decide(r, "reject");
    } else {
      return;
    }
    event.preventDefault();
  };
  window.addEventListener("keydown", onKey);
  void load();
  return { element, dispose: () => window.removeEventListener("keydown", onKey) };
}

/// Justification de la décision : obligatoire pour un rejet (UI-UX §3.4),
/// facultative pour une approbation. `null` si l'opérateur renonce.
function askComment(kind: "approve" | "reject"): Promise<string | null> {
  return new Promise((resolve) => {
    const required = kind === "reject";
    const input = h("textarea", {
      id: "decision-comment",
      rows: "3",
      maxlength: "1000",
      "data-testid": "comment",
      ...(required ? { required: "" } : {}),
    });
    const next = h("button", { type: "submit", class: "primary", "data-testid": "comment-next" }, "Préparer la signature");
    const cancel = h("button", { type: "button" }, "Annuler");
    const form = h(
      "form",
      { method: "dialog" },
      h("h2", {}, kind === "reject" ? "Motif du rejet (obligatoire)" : "Commentaire (facultatif)"),
      h("label", { for: "decision-comment" }, "Justification consignée au journal"),
      input,
      h("div", { class: "actions" }, cancel, next),
    );
    const dialog = h("dialog", { class: "signature", "data-testid": "comment-dialog" }, form);
    const finish = (value: string | null): void => {
      dialog.close();
      dialog.remove();
      resolve(value);
    };
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const value = input.value.trim();
      if (required && value === "") {
        input.focus();
        return;
      }
      finish(value);
    });
    cancel.addEventListener("click", () => finish(null));
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      finish(null);
    });
    document.body.append(dialog);
    dialog.showModal();
    input.focus();
  });
}
