// Dossiers d'incident (docs/UI-UX.md §2, docs/WEBUI.md §6, §15 étape 5c) : un
// dossier regroupe et justifie, il ne décide de rien sur la PKI. On y consigne
// des notes et la référence d'actions déjà figées par l'autorité ; sa clôture
// est irréversible et signée avec la clé de l'opérateur, sur le corps exact
// affiché dans la modale.
//
// Les boutons d'écriture ne sont proposés qu'aux rôles qui peuvent écrire :
// c'est un confort, la console refuse de toute façon les autres.

import { call, isError, type Me } from "./api";
import { h, replace } from "./dom";
import { groupedHash, utc } from "./format";
import { sign } from "./sign";
import type { View } from "./view";

interface Incident {
  id: string;
  title: string;
  state: "OUVERT" | "CLOS";
  opened_by: string;
  opened_at: string;
  closed_by: string | null;
  closed_at: string | null;
  closing_note: string | null;
}

interface Entry {
  id: string;
  at: string;
  operator: string;
  kind: "note" | "action_liee";
  detail: string;
  action_id: string | null;
  body_hash: string | null;
  action: string | null;
  executed: boolean | null;
}

interface Detail extends Incident {
  actions: Entry[];
  closure: { credential_id: string; body: string; body_hash: string; verified_at: string } | null;
}

const ACTIONS: Record<string, string> = {
  approve_request: "Approbation d'une demande",
  reject_request: "Rejet d'une demande",
  revoke_certificate: "Révocation de certificat",
  invite_operator: "Invitation d'un opérateur",
  confirm_key: "Confirmation d'une clé",
  revoke_key: "Révocation d'une clé",
  set_role: "Changement de rôle",
};

const MESSAGES: Record<string, string> = {
  forbidden: "Votre rôle ne permet pas d'écrire dans un dossier d'incident.",
  incident_closed: "Ce dossier est clos : il ne reçoit plus rien.",
  unknown_action: "Aucune action ne porte cet identifiant.",
  already_linked: "Cette action est déjà rattachée à ce dossier.",
  unknown_incident: "Ce dossier n'existe pas.",
  unavailable: "Service indisponible : rien n'a été enregistré.",
};

function explain(body: unknown, fallback: string): string {
  if (isError(body)) return MESSAGES[body.error] ?? body.message;
  return fallback;
}

export function incidentsView(me: Me, onChanged: () => void): View {
  const mayWrite = me.role === "ra_operateur" || me.role === "ca_operateur";
  let rows: Incident[] = [];
  let selected: string | null = null;
  let filter: "OUVERT" | "CLOS" | "" = "OUVERT";

  const notice = h("p", { class: "status", role: "status", "aria-live": "polite", "data-testid": "incidents-status" });
  const body = h("tbody", {});
  const inspector = h("aside", { class: "inspector", "aria-label": "Dossier", "data-testid": "incident" });

  const state = h(
    "select",
    { id: "incident-filter", "data-testid": "incident-filter" },
    h("option", { value: "OUVERT" }, "Ouverts"),
    h("option", { value: "CLOS" }, "Clos"),
    h("option", { value: "" }, "Tous"),
  );
  state.addEventListener("change", () => {
    filter = state.value as typeof filter;
    selected = null;
    void load();
  });

  const title = h("input", {
    id: "incident-title",
    type: "text",
    maxlength: "200",
    required: "",
    placeholder: "Objet du dossier (ex. signalement CERT-FR 2026-991)",
    "data-testid": "incident-title",
  });
  const filterField = h("label", { for: "incident-filter" }, "Afficher", state);
  const openForm = h(
    "form",
    { class: "filters incident-bar", "data-testid": "incident-open" },
    h("label", { for: "incident-title" }, "Ouvrir un dossier", title),
    h("button", { type: "submit", class: "primary", "data-testid": "incident-open-submit" }, "Ouvrir"),
    filterField,
  );
  openForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void open();
  });

  const element = h(
    "section",
    {},
    h("h1", {}, "Dossiers d'incident"),
    notice,
    mayWrite ? openForm : h("div", { class: "filters narrow" }, filterField),
    h(
      "div",
      { class: "split" },
      h(
        "table",
        { class: "dense", "data-testid": "incidents" },
        h("thead", {}, h("tr", {}, h("th", {}, "État"), h("th", {}, "Objet"), h("th", {}, "Ouvert par"), h("th", {}, "Ouvert le"))),
        body,
      ),
      inspector,
    ),
  );

  const badge = (i: Incident): HTMLElement =>
    i.state === "OUVERT"
      ? h("span", { class: "badge pending" }, "○ ouvert")
      : h("span", { class: "badge closed" }, "■ clos");

  const renderRows = (): void => {
    if (rows.length === 0) {
      replace(body, h("tr", {}, h("td", { colspan: "4", class: "muted" }, "Aucun dossier dans cet état.")));
      return;
    }
    replace(
      body,
      ...rows.map((i) => {
        const tr = h(
          "tr",
          { "aria-selected": String(i.id === selected), "data-testid": `incident-${i.id}` },
          h("td", {}, badge(i)),
          h("td", {}, i.title),
          h("td", {}, i.opened_by),
          h("td", { class: "mono" }, utc(i.opened_at)),
        );
        tr.addEventListener("click", () => {
          selected = i.id;
          renderRows();
          void show();
        });
        return tr;
      }),
    );
  };

  const entry = (e: Entry): HTMLElement => {
    const head = h("p", { class: "muted" }, h("span", { class: "mono" }, utc(e.at)), ` — ${e.operator}`);
    if (e.kind === "note") {
      return h("li", { class: "entry", "data-testid": "entry-note" }, head, h("p", { class: "note" }, e.detail));
    }
    const label = e.action === null ? "Action" : (ACTIONS[e.action] ?? e.action);
    return h(
      "li",
      { class: "entry", "data-testid": "entry-action" },
      head,
      h(
        "p",
        {},
        `Action rattachée : ${label} `,
        h("span", { class: e.executed ? "badge valid" : "badge pending" }, e.executed ? "● exécutée" : "○ non exécutée"),
      ),
      h(
        "dl",
        {},
        h("dt", {}, "Identifiant"),
        h("dd", { class: "mono" }, e.action_id ?? "—"),
        h("dt", {}, "Empreinte du corps"),
        h("dd", { class: "mono hash" }, e.body_hash === null ? "—" : groupedHash(e.body_hash)),
      ),
      e.detail === "" ? null : h("p", { class: "note" }, e.detail),
    );
  };

  const render = (d: Detail): void => {
    const parts: (HTMLElement | null)[] = [
      h("h2", {}, d.title),
      h(
        "dl",
        {},
        h("dt", {}, "État"),
        h("dd", { "data-testid": "incident-state" }, badge(d)),
        h("dt", {}, "Ouvert par"),
        h("dd", {}, d.opened_by),
        h("dt", {}, "Ouvert le"),
        h("dd", { class: "mono" }, utc(d.opened_at)),
      ),
      h("h2", {}, "Chronologie"),
      d.actions.length === 0
        ? h("p", { class: "muted" }, "Rien n'a encore été consigné dans ce dossier.")
        : h("ol", { class: "timeline", "data-testid": "timeline" }, ...d.actions.map(entry)),
    ];
    if (d.state === "CLOS") {
      parts.push(
        h("h2", {}, "Clôture"),
        h(
          "dl",
          { "data-testid": "closure" },
          h("dt", {}, "Clos par"),
          h("dd", {}, d.closed_by ?? "—"),
          h("dt", {}, "Clos le"),
          h("dd", { class: "mono" }, d.closed_at === null ? "—" : utc(d.closed_at)),
          h("dt", {}, "Justification"),
          h("dd", { class: "note", "data-testid": "closing-note" }, d.closing_note ?? "—"),
          h("dt", {}, "Empreinte signée"),
          h("dd", { class: "mono hash" }, d.closure === null ? "—" : groupedHash(d.closure.body_hash)),
          h("dt", {}, "Clé"),
          h("dd", { class: "mono key-id" }, d.closure?.credential_id ?? "—"),
        ),
      );
    } else if (mayWrite) {
      parts.push(writing(d));
    }
    replace(inspector, ...parts.filter((p): p is HTMLElement => p !== null));
  };

  const writing = (d: Detail): HTMLElement => {
    const note = h("textarea", { id: "incident-note", rows: "3", maxlength: "2000", required: "", "data-testid": "note" });
    const noteForm = h(
      "form",
      {},
      h("label", { for: "incident-note" }, "Consigner une note"),
      note,
      h("div", { class: "actions start" }, h("button", { type: "submit", "data-testid": "note-submit" }, "Consigner")),
    );
    noteForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void add(d, { kind: "note", detail: note.value });
    });

    const action = h("input", {
      id: "incident-action",
      type: "text",
      required: "",
      class: "mono",
      placeholder: "identifiant de l'action (salle de quorum, audit)",
      "data-testid": "link-action",
    });
    const comment = h("input", { id: "incident-action-comment", type: "text", maxlength: "2000", "data-testid": "link-comment" });
    const linkForm = h(
      "form",
      {},
      h("label", { for: "incident-action" }, "Rattacher une action de l'autorité"),
      action,
      h("label", { for: "incident-action-comment" }, "Commentaire (facultatif)"),
      comment,
      h("p", { class: "muted" }, "Le dossier désigne l'action, il ne l'exécute pas : son empreinte est relue chez l'autorité."),
      h("div", { class: "actions start" }, h("button", { type: "submit", "data-testid": "link-submit" }, "Rattacher")),
    );
    linkForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void add(d, { kind: "action_liee", action_id: action.value.trim(), detail: comment.value });
    });

    const close = h("button", { type: "button", class: "danger", "data-testid": "close" }, "Clore le dossier…");
    close.addEventListener("click", () => void startClosing(d));
    return h(
      "div",
      { class: "writing" },
      h("h2", {}, "Consigner"),
      noteForm,
      linkForm,
      h("p", { class: "muted" }, "La clôture est définitive et signée avec votre clé : un dossier clos ne reçoit plus rien."),
      h("div", { class: "actions" }, close),
    );
  };

  const open = async (): Promise<void> => {
    const reply = await call<Incident>("POST", "/api/v1/incidents", { title: title.value });
    if (reply.status !== 201 || reply.body === null || isError(reply.body)) {
      notice.textContent = explain(reply.body, "Le dossier n'a pas pu être ouvert.");
      return;
    }
    title.value = "";
    selected = reply.body.id;
    notice.textContent = "Dossier ouvert.";
    if (filter === "CLOS") {
      filter = "OUVERT";
      state.value = "OUVERT";
    }
    await load();
    onChanged();
  };

  const add = async (d: Detail, body: Record<string, string>): Promise<void> => {
    const reply = await call<Entry>("POST", `/api/v1/incidents/${d.id}/actions`, body);
    if (reply.status !== 201 || reply.body === null || isError(reply.body)) {
      notice.textContent = explain(reply.body, "Rien n'a été consigné.");
      // Un dossier clos entre temps : l'afficher tel qu'il est.
      if (isError(reply.body) && reply.body.error === "incident_closed") await load();
      return;
    }
    notice.textContent = body.kind === "note" ? "Note consignée." : "Action rattachée.";
    await show();
  };

  const startClosing = async (d: Detail): Promise<void> => {
    const justification = await askClosingNote(d);
    if (justification === null) return;
    const result = await sign({
      title: "Clôture d'un dossier d'incident",
      summary: [
        ["Action", "clore définitivement le dossier"],
        ["Dossier", d.title],
        ["Entrées consignées", String(d.actions.length)],
        ["Justification", justification],
      ],
      action: {},
      prepare: { route: `/api/v1/incidents/${d.id}/close/challenge`, body: { closing_note: justification } },
      route: `/api/v1/incidents/${d.id}/close`,
      done: "✓ Dossier clos.",
    });
    if (result === null) return;
    notice.textContent = "Dossier clos.";
    // Le dossier clos reste affiché, même si la liste ne montre que les ouverts.
    await load();
    onChanged();
  };

  const show = async (): Promise<void> => {
    if (selected === null) {
      replace(inspector, h("p", { class: "muted" }, "Aucun dossier sélectionné."));
      return;
    }
    const reply = await call<Detail>("GET", `/api/v1/incidents/${selected}`);
    if (reply.status !== 200 || reply.body === null || isError(reply.body)) {
      replace(inspector, h("p", { class: "muted" }, explain(reply.body, "Dossier indisponible.")));
      return;
    }
    render(reply.body);
  };

  const load = async (): Promise<void> => {
    const reply = await call<Incident[]>("GET", `/api/v1/incidents${filter === "" ? "" : `?state=${filter}`}`);
    rows = Array.isArray(reply.body) ? reply.body : [];
    if (isError(reply.body)) notice.textContent = reply.body.message;
    // On garde le dossier affiché s'il a quitté la liste (il vient d'être
    // clos) ; sinon le premier de la liste.
    selected ??= rows[0]?.id ?? null;
    renderRows();
    await show();
  };

  void load();
  return { element, dispose: () => undefined };
}

/// La friction voulue pour un geste irréversible (UI-UX §1) : une
/// justification obligatoire, saisie avant toute signature.
function askClosingNote(d: Detail): Promise<string | null> {
  return new Promise((resolve) => {
    const note = h("textarea", { id: "closing-note", rows: "4", maxlength: "2000", required: "", "data-testid": "closing-note-input" });
    const next = h("button", { type: "submit", class: "danger", "data-testid": "closing-next" }, "Préparer la signature");
    const cancel = h("button", { type: "button" }, "Annuler");
    const form = h(
      "form",
      { method: "dialog" },
      h("h2", {}, "Clôture : justification"),
      h("p", { class: "muted" }, `Dossier : ${d.title}`),
      h("label", { for: "closing-note" }, "Justification consignée au journal et signée (obligatoire)"),
      note,
      h("div", { class: "actions" }, cancel, next),
    );
    const dialog = h("dialog", { class: "signature", "data-testid": "closing-dialog" }, form);
    const finish = (value: string | null): void => {
      dialog.close();
      dialog.remove();
      resolve(value);
    };
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const text = note.value.trim();
      if (text === "") return;
      finish(text);
    });
    cancel.addEventListener("click", () => finish(null));
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      finish(null);
    });
    document.body.append(dialog);
    dialog.showModal();
    note.focus();
  });
}
