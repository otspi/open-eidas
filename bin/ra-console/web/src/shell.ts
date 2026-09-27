// Le poste de travail une fois connecté (docs/UI-UX.md §2) : barre de
// sécurité (environnement, identité et rôle relus sur le serveur), navigation
// latérale avec les compteurs des files, zone de travail. Les écrans métier
// commencent par la file des demandes (6b) ; révocation, quorum et audit suivent.

import { call, isError, type ConsoleInfo, type Me } from "./api";
import { banner } from "./banner";
import { h, replace } from "./dom";
import { certificatesView } from "./certificates";
import { operatorsView } from "./operators";
import { quorumView } from "./quorum";
import { requestsView } from "./requests";
import type { View } from "./view";

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
  const refresh = (): void => void refreshCounts(requests, quorum);
  const work = h("main", { class: "workspace", tabindex: "-1" });
  let current: View | null = null;
  const views: [string, string, HTMLElement | null, () => View][] = [
    ["requests", "Demandes RA ", requests, () => requestsView(refresh)],
    ["certificates", "Certificats", null, () => certificatesView(refresh)],
    ["quorum", "Quorum ", quorum, () => quorumView(me, refresh)],
    ["operators", "Opérateurs", null, () => operatorsView(me)],
  ];
  const buttons = views.map(([id, label, count, make]) => {
    const button = h("button", { type: "button", class: "nav", "data-testid": `nav-${id}` }, label, count);
    button.addEventListener("click", () => show(id, make));
    return button;
  });
  const show = (id: string, make: () => View): void => {
    current?.dispose();
    current = make();
    replace(work, current.element);
    for (const b of buttons) b.setAttribute("aria-current", String(b.dataset.testid === `nav-${id}`));
  };
  const nav = h("nav", { class: "sidebar", "aria-label": "Files de travail" }, h("ul", {}, ...buttons.map((b) => h("li", {}, b))));
  replace(root, banner(info), bar, h("div", { class: "layout" }, nav, work));
  const first = views[0]!;
  show(first[0], first[3]);
  refresh();
  return () => current?.dispose();
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
