// Le poste de travail une fois connecté (docs/UI-UX.md §2) : barre de
// sécurité (environnement, identité et rôle relus sur le serveur), navigation
// latérale avec les compteurs des files, zone de travail. Les écrans métier
// commencent par la file des demandes (6b) ; révocation, quorum et audit suivent.

import { call, isError, type ConsoleInfo, type Me } from "./api";
import { banner } from "./banner";
import { h, replace } from "./dom";
import { requestsView } from "./requests";

const ROLE_LABELS: Record<Me["role"], string> = {
  auditeur: "auditeur",
  ra_operateur: "opérateur RA",
  ca_operateur: "opérateur CA",
  admin: "administrateur",
};

export function renderShell(root: HTMLElement, info: ConsoleInfo, me: Me, onLogout: () => void): () => void {
  const logout = h("button", { type: "button", class: "quiet", "data-testid": "logout" }, "Se déconnecter");
  logout.addEventListener("click", onLogout);
  const bar = h(
    "header",
    { class: "security-bar" },
    h("span", { class: "brand" }, "Open eIDAS"),
    h(
      "span",
      { class: "identity" },
      h("span", { class: "operator", "data-testid": "operator" }, me.operator),
      h("span", { class: `role role-${me.role}`, "data-testid": "role" }, ROLE_LABELS[me.role]),
    ),
    logout,
  );
  const requests = h("span", { class: "count", "data-testid": "count-requests" }, "…");
  const quorum = h("span", { class: "count", "data-testid": "count-quorum" }, "…");
  const nav = h(
    "nav",
    { class: "sidebar", "aria-label": "Files de travail" },
    h("ul", {}, h("li", {}, "Demandes RA ", requests), h("li", {}, "Quorum ", quorum)),
  );
  const view = requestsView(() => void refreshCounts(requests, quorum));
  const work = h("main", { class: "workspace", tabindex: "-1" }, view.element);
  replace(root, banner(info), bar, h("div", { class: "layout" }, nav, work));
  void refreshCounts(requests, quorum);
  return view.dispose;
}

async function refreshCounts(requests: HTMLElement, quorum: HTMLElement): Promise<void> {
  const [pending, waiting] = await Promise.all([
    call<unknown[]>("GET", "/api/v1/requests?state=PENDING"),
    call<unknown[]>("GET", "/api/v1/quorum?state=PENDING"),
  ]);
  requests.textContent = Array.isArray(pending.body) ? `(${pending.body.length})` : "(—)";
  quorum.textContent = Array.isArray(waiting.body) ? `(${waiting.body.length})` : "(—)";
  if (isError(pending.body) || isError(waiting.body)) {
    requests.title = quorum.title = "compteur indisponible";
  }
}

export function idleWarning(root: HTMLElement): HTMLElement {
  const warning = h(
    "div",
    { class: "idle-warning", role: "alert", "data-testid": "idle-warning" },
    "Session inactive : verrouillage dans une minute. Une action au clavier ou à la souris la prolonge.",
  );
  root.prepend(warning);
  return warning;
}
