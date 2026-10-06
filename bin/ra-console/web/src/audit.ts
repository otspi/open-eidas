// Explorateur d'audit (docs/UI-UX.md §3.3, docs/WEBUI.md §7, §15 étape 6d) :
// recherche en lecture seule dans les deux journaux chaînés, `ca-server` (qui
// fait foi pour la PKI) et `ra-console`. L'API relit et vérifie les deux
// chaînes avant de répondre ; une chaîne rompue ne renvoie aucun résultat et
// l'écran le dit en bloc, sans rien afficher à côté (« personne ne peut
// l'ignorer par inattention »).

import { call, isError } from "./api";
import { h, replace } from "./dom";
import { utc } from "./format";
import type { View } from "./view";

interface Entry {
  source: "ca-server" | "ra-console";
  sequence: number;
  at: string;
  event: string;
  data?: Record<string, unknown>;
}

interface Report {
  chain_verified: boolean;
  entries_checked: number;
  results: Entry[];
}

const SOURCES: Record<Entry["source"], string> = {
  "ca-server": "Autorité",
  "ra-console": "Console",
};

/// L'opérateur d'un événement : `ca-server` l'écrit `operateur`, la console
/// `operator`. Aucun des deux n'est garanti (une émission n'a pas d'opérateur),
/// d'où un champ vide plutôt qu'une valeur inventée.
export function operatorOf(entry: Entry): string {
  for (const key of ["operateur", "operator"]) {
    const value = entry.data?.[key];
    if (typeof value === "string" && value !== "") return value;
  }
  return "";
}

/// Les filtres « opérateur » et « événement » s'appliquent dans le navigateur
/// aux résultats reçus : l'API ne filtre que par série et par période.
export function narrow(entries: Entry[], operator: string, event: string): Entry[] {
  const wanted = operator.trim().toLowerCase();
  return entries.filter(
    (e) => (event === "" || e.event === event) && (wanted === "" || operatorOf(e).toLowerCase().includes(wanted)),
  );
}

/// Bornes d'une période saisie en jours (UTC) : du premier instant du jour
/// de début au dernier du jour de fin.
export function bound(day: string, end: boolean): string {
  return day === "" ? "" : `${day}T${end ? "23:59:59" : "00:00:00"}Z`;
}

function padded(sequence: number): string {
  return `#${String(sequence).padStart(8, "0")}`;
}

export function auditView(): View {
  let entries: Entry[] = [];
  const serial = h("input", { type: "text", name: "serial", "data-testid": "audit-serial", autocomplete: "off", spellcheck: "false" });
  const from = h("input", { type: "date", name: "from", "data-testid": "audit-from" });
  const to = h("input", { type: "date", name: "to", "data-testid": "audit-to" });
  const operator = h("input", { type: "text", name: "operator", "data-testid": "audit-operator", autocomplete: "off" });
  const event = h("select", { "data-testid": "audit-event" });
  const submit = h("button", { type: "submit", class: "primary", "data-testid": "audit-submit" }, "Rechercher");
  const field = (label: string, control: HTMLElement): HTMLElement => h("label", {}, label, control);
  const form = h(
    "form",
    { class: "filters", "aria-label": "Recherche dans le journal" },
    field("Numéro de série (hexadécimal)", serial),
    field("Du", from),
    field("Au", to),
    field("Opérateur (dans les résultats)", operator),
    field("Événement (dans les résultats)", event),
    submit,
  );
  const banner = h("div", { "data-testid": "audit-banner" });
  const body = h("tbody", {});
  const table = h(
    "table",
    { class: "dense", "data-testid": "audit-results" },
    h(
      "thead",
      {},
      h(
        "tr",
        {},
        h("th", {}, "Journal"),
        h("th", {}, "Séquence"),
        h("th", {}, "Date"),
        h("th", {}, "Opérateur"),
        h("th", {}, "Événement"),
        h("th", {}, h("span", { class: "sr-only" }, "Détail")),
      ),
    ),
    body,
  );
  table.hidden = true;
  const element = h("section", {}, h("h1", {}, "Journal d'audit"), form, banner, table);

  const row = (e: Entry): HTMLElement[] => {
    const key = `${e.source}-${e.sequence}`;
    const toggle = h("button", { type: "button", class: "quiet", "aria-expanded": "false", "data-testid": `audit-toggle-${key}` }, "Détail");
    const detail = h("tr", { class: "detail", hidden: "", "data-testid": `audit-detail-${key}` });
    const cell = h("td", { colspan: "6" }, h("pre", { class: "mono" }, JSON.stringify(e.data ?? {}, null, 2)));
    detail.append(cell);
    toggle.addEventListener("click", () => {
      const open = detail.hidden;
      detail.hidden = !open;
      toggle.setAttribute("aria-expanded", String(open));
    });
    const line = h(
      "tr",
      { "data-testid": `audit-row-${key}` },
      h("td", {}, h("span", { class: `badge source-${e.source}` }, SOURCES[e.source] ?? e.source)),
      h("td", { class: "mono" }, padded(e.sequence)),
      h("td", { class: "mono" }, utc(e.at)),
      h("td", {}, operatorOf(e) || "—"),
      h("td", { class: "mono" }, e.event),
      h("td", {}, toggle),
    );
    return [line, detail];
  };

  const render = (): void => {
    const shown = narrow(entries, operator.value, event.value);
    replace(body, ...shown.flatMap(row));
    table.hidden = shown.length === 0;
    const note = banner.querySelector("[data-testid=audit-count]");
    if (note !== null) {
      note.textContent = shown.length === entries.length ? `${entries.length} résultat(s)` : `${shown.length} résultat(s) sur ${entries.length} reçus`;
    }
  };

  const refreshEvents = (): void => {
    const kept = event.value;
    const kinds = [...new Set(entries.map((e) => e.event))].sort();
    replace(event, h("option", { value: "" }, "Tous"), ...kinds.map((k) => h("option", { value: k }, k)));
    event.value = kinds.includes(kept) ? kept : "";
  };

  const blocked = (message: string): void => {
    entries = [];
    refreshEvents();
    table.hidden = true;
    replace(body);
    replace(banner, h("div", { class: "audit-alert", role: "alert", "data-testid": "audit-broken" }, message));
  };

  const search = async (): Promise<void> => {
    const params = new URLSearchParams();
    if (serial.value.trim() !== "") params.set("serial", serial.value.trim());
    if (from.value !== "") params.set("from", bound(from.value, false));
    if (to.value !== "") params.set("to", bound(to.value, true));
    const query = params.toString();
    replace(banner, h("p", { class: "status", role: "status" }, "Vérification des deux journaux…"));
    const reply = await call<Report>("GET", `/api/v1/audit/search${query === "" ? "" : `?${query}`}`);
    if (isError(reply.body) || reply.body === null) {
      blocked(
        reply.body !== null && isError(reply.body)
          ? `Journal indisponible : ${reply.body.message}. Aucune vérification n'a pu être faite, rien n'est affiché.`
          : "Journal indisponible. Aucune vérification n'a pu être faite, rien n'est affiché.",
      );
      return;
    }
    if (!reply.body.chain_verified) {
      blocked(
        "RUPTURE D'INTÉGRITÉ DÉTECTÉE : l'un des deux journaux est rompu ou illisible. Aucun résultat n'est affiché tant que la chaîne n'est pas rétablie ; prévenez un administrateur.",
      );
      return;
    }
    entries = reply.body.results;
    refreshEvents();
    replace(
      banner,
      h(
        "div",
        { class: "audit-ok", role: "status", "data-testid": "audit-verified" },
        `Chaîne d'audit vérifiée : ${reply.body.entries_checked} entrées intègres dans les deux journaux.`,
      ),
      h("p", { class: "status", "data-testid": "audit-count" }),
    );
    render();
  };

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void search();
  });
  operator.addEventListener("input", render);
  event.addEventListener("change", render);

  refreshEvents();
  void search();
  return { element, dispose: () => undefined };
}
