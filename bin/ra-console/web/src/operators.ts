// Registre des opérateurs (docs/WEBUI.md §10, §15 étape 6e) : invitations,
// confirmation des clés en attente (empreinte comparée hors bande), révocation
// de clé, changement de rôle. Chaque écriture est une action signée que
// ca-server juge ; les boutons ne sont qu'un affichage pour les non-admins.

import { call, isError, type Me } from "./api";
import { h, replace } from "./dom";
import { utc } from "./format";
import { sign } from "./sign";
import type { View } from "./view";

interface Credential {
  credential_id: string;
  label: string;
  initiated_at: string;
  revoked_at: string | null;
}
interface Operator {
  name: string;
  role: Me["role"];
  disabled: boolean;
  credentials: Credential[];
}
interface PendingKey {
  credential_id: string;
  operator: string;
  key_fingerprint: string | null;
  registered_at: string;
  expires_at: string;
}
interface Registry {
  operators: Operator[];
  pending: PendingKey[];
}

const ROLES: [Me["role"], string][] = [
  ["auditeur", "auditeur"],
  ["ra_operateur", "opérateur RA"],
  ["ca_operateur", "opérateur CA"],
  ["admin", "administrateur"],
];

export function operatorsView(me: Me): View {
  const isAdmin = me.role === "admin";
  const notice = h("p", { class: "status", role: "status", "aria-live": "polite", "data-testid": "operators-status" });
  const table = h("tbody", {});
  const inspector = h("aside", { class: "inspector", "aria-label": "Inspecteur" });
  const pendingList = h("div", { class: "quorum", "data-testid": "pending-keys" });
  const invite = h("button", { type: "button", class: "primary", "data-testid": "invite", ...(isAdmin ? {} : { disabled: "" }) }, "Inviter un opérateur…");
  const element = h(
    "section",
    {},
    h("h1", {}, "Opérateurs"),
    isAdmin ? null : h("p", { class: "muted" }, "Consultation seule : la gestion du registre est réservée aux administrateurs."),
    notice,
    h("div", { class: "actions start" }, invite),
    h(
      "div",
      { class: "split" },
      h(
        "table",
        { class: "dense", "data-testid": "operators" },
        h("thead", {}, h("tr", {}, h("th", {}, "Opérateur"), h("th", {}, "Rôle"), h("th", {}, "Clés actives"), h("th", {}, "État"))),
        table,
      ),
      inspector,
    ),
    h("h2", {}, "Clés en attente de confirmation"),
    pendingList,
  );
  let registry: Registry = { operators: [], pending: [] };
  let selected = 0;

  const active = (o: Operator): Credential[] => o.credentials.filter((c) => c.revoked_at === null);

  const render = (): void => {
    replace(
      table,
      ...registry.operators.map((o, i) => {
        const tr = h(
          "tr",
          { "aria-selected": String(i === selected), "data-testid": `operator-${o.name}` },
          h("td", {}, o.name),
          h("td", {}, h("span", { class: `role role-${o.role}` }, o.role)),
          h("td", { class: "mono" }, String(active(o).length)),
          h("td", {}, o.disabled ? "désactivé" : "actif"),
        );
        tr.addEventListener("click", () => {
          selected = i;
          render();
        });
        return tr;
      }),
    );
    renderInspector();
    replace(
      pendingList,
      ...(registry.pending.length === 0
        ? [h("p", { class: "muted" }, "Aucune clé en attente.")]
        : registry.pending.map((p) => {
            const confirm = h(
              "button",
              { type: "button", class: "primary", "data-testid": `confirm-${p.operator}`, ...(isAdmin && p.key_fingerprint ? {} : { disabled: "" }) },
              "Confirmer la clé…",
            );
            confirm.addEventListener("click", () => void confirmKey(p));
            return h(
              "article",
              { class: "card" },
              h("h2", {}, `Clé de ${p.operator}`),
              h(
                "dl",
                {},
                h("dt", {}, "Empreinte"),
                h("dd", { class: "mono hash" }, p.key_fingerprint ?? "illisible"),
                h("dt", {}, "Enregistrée le"),
                h("dd", { class: "mono" }, utc(p.registered_at)),
                h("dt", {}, "Expire le"),
                h("dd", { class: "mono" }, utc(p.expires_at)),
              ),
              h("div", { class: "actions" }, confirm),
            );
          })),
    );
  };

  const renderInspector = (): void => {
    const o = registry.operators[selected];
    if (o === undefined) {
      replace(inspector, h("p", { class: "muted" }, "Aucun opérateur."));
      return;
    }
    const roleSelect = h(
      "select",
      { id: "new-role", "data-testid": "new-role", ...(isAdmin ? {} : { disabled: "" }) },
      ...ROLES.map(([value, label]) => {
        const option = h("option", { value }, label);
        if (value === o.role) option.selected = true;
        return option;
      }),
    );
    const changeRole = h("button", { type: "button", "data-testid": "change-role", ...(isAdmin ? {} : { disabled: "" }) }, "Changer le rôle…");
    changeRole.addEventListener("click", () => void setRole(o, roleSelect.value as Me["role"]));
    replace(
      inspector,
      h("h2", {}, o.name),
      h("label", { for: "new-role" }, "Rôle"),
      roleSelect,
      h("div", { class: "actions" }, changeRole),
      h("h2", {}, "Clés"),
      ...o.credentials.map((c) => {
        const revoke = h(
          "button",
          { type: "button", class: "danger", "data-testid": `revoke-key-${o.name}`, ...(isAdmin && c.revoked_at === null ? {} : { disabled: "" }) },
          "Révoquer…",
        );
        revoke.addEventListener("click", () => void revokeKey(o, c));
        return h(
          "div",
          { class: "key" },
          h("p", { class: "mono" }, `${c.label} · ${c.credential_id.slice(0, 16)}…`),
          h("p", { class: "muted" }, c.revoked_at ? `révoquée le ${utc(c.revoked_at)}` : `active depuis le ${utc(c.initiated_at)}`),
          revoke,
        );
      }),
    );
  };

  const load = async (): Promise<void> => {
    const reply = await call<Registry>("GET", "/api/v1/operators");
    if (reply.status === 200 && reply.body !== null && !isError(reply.body)) registry = reply.body;
    else if (isError(reply.body)) notice.textContent = reply.body.message;
    selected = Math.min(selected, Math.max(registry.operators.length - 1, 0));
    render();
  };

  const after = async (result: Record<string, unknown> | null, done: string): Promise<void> => {
    if (result === null) return;
    notice.textContent =
      result.status === "AWAITING_QUORUM" ? "Signature enregistrée : un second administrateur doit co-signer (salle de quorum)." : done;
    await load();
  };

  const setRole = async (o: Operator, role: Me["role"]): Promise<void> => {
    if (role === o.role) return;
    const result = await sign({
      title: `Changement de rôle de ${o.name}`,
      summary: [
        ["Opérateur", o.name],
        ["Rôle actuel", o.role],
        ["Nouveau rôle", role],
      ],
      action: { action: "set_role", operator: o.name, role },
      route: `/api/v1/operators/${encodeURIComponent(o.name)}/role`,
    });
    await after(result, `Rôle de ${o.name} : ${role}.`);
  };

  const revokeKey = async (o: Operator, c: Credential): Promise<void> => {
    const reason = await ask("Motif de la révocation de la clé (obligatoire)", "revoke-reason");
    if (reason === null) return;
    const result = await sign({
      title: `Révocation d'une clé de ${o.name}`,
      summary: [
        ["Opérateur", o.name],
        ["Clé", `${c.label} · ${c.credential_id}`],
        ["Motif", reason],
      ],
      action: { action: "revoke_key", credential_id: c.credential_id, reason },
      route: `/api/v1/credentials/${encodeURIComponent(c.credential_id)}/revoke`,
    });
    await after(result, `Clé de ${o.name} révoquée.`);
  };

  const confirmKey = async (p: PendingKey): Promise<void> => {
    if (p.key_fingerprint === null) return;
    const checked = await confirmFingerprint(p);
    if (!checked) return;
    const result = await sign({
      title: `Confirmation de la clé de ${p.operator}`,
      summary: [
        ["Opérateur", p.operator],
        ["Empreinte comparée", p.key_fingerprint],
      ],
      action: { action: "confirm_key", credential_id: p.credential_id, key_fingerprint: p.key_fingerprint },
      route: `/api/v1/credentials/${encodeURIComponent(p.credential_id)}/confirm`,
    });
    await after(result, `Clé de ${p.operator} confirmée.`);
  };

  invite.addEventListener("click", () => void inviteOperator());
  const inviteOperator = async (): Promise<void> => {
    const who = await askInvite();
    if (who === null) return;
    const result = await sign({
      title: `Invitation de ${who.name}`,
      summary: [
        ["Opérateur invité", who.name],
        ["Rôle", who.role],
      ],
      action: { action: "invite_operator", name: who.name, role: who.role },
      route: "/api/v1/operators",
    });
    if (result === null) return;
    const inner = result.result as { invite_token?: string } | null | undefined;
    if (result.status === "EXECUTED" && typeof inner?.invite_token === "string") {
      await showToken(who.name, inner.invite_token);
    }
    await after(result, `Invitation de ${who.name} créée.`);
  };

  void load();
  return { element, dispose: () => undefined };
}

/// Le jeton d'invitation, affiché une seule fois : il n'est conservé nulle part,
/// ni par la console ni par ca-server (seul son haché l'est).
function showToken(name: string, token: string): Promise<void> {
  return new Promise((resolve) => {
    const close = h("button", { type: "button", class: "primary", "data-testid": "token-close" }, "J'ai transmis le jeton");
    const dialog = h(
      "dialog",
      { class: "signature", "data-testid": "token-dialog" },
      h("h2", {}, `Jeton d'invitation de ${name}`),
      h("p", {}, "Affiché une seule fois. Transmettez-le à l'invité par un canal distinct ; il lui sert à enregistrer sa clé FIDO2."),
      h("pre", { class: "mono", "data-testid": "invite-token" }, token),
      h("div", { class: "actions" }, close),
    );
    const finish = (): void => {
      dialog.close();
      dialog.remove();
      resolve();
    };
    close.addEventListener("click", finish);
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      finish();
    });
    document.body.append(dialog);
    dialog.showModal();
  });
}

function formDialog(testid: string, title: string, fields: HTMLElement[], valid: () => boolean): Promise<boolean> {
  return new Promise((resolve) => {
    const next = h("button", { type: "submit", class: "primary", "data-testid": "comment-next" }, "Préparer la signature");
    const cancel = h("button", { type: "button" }, "Annuler");
    const form = h("form", { method: "dialog" }, h("h2", {}, title), ...fields, h("div", { class: "actions" }, cancel, next));
    const dialog = h("dialog", { class: "signature", "data-testid": testid }, form);
    const finish = (ok: boolean): void => {
      dialog.close();
      dialog.remove();
      resolve(ok);
    };
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (valid()) finish(true);
    });
    cancel.addEventListener("click", () => finish(false));
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      finish(false);
    });
    document.body.append(dialog);
    dialog.showModal();
  });
}

async function ask(title: string, testid: string): Promise<string | null> {
  const input = h("textarea", { rows: "3", maxlength: "1000", required: "", "data-testid": "comment" });
  const ok = await formDialog(testid, title, [input], () => input.value.trim() !== "");
  return ok ? input.value.trim() : null;
}

async function askInvite(): Promise<{ name: string; role: Me["role"] } | null> {
  const name = h("input", { id: "invite-name", required: "", maxlength: "100", "data-testid": "invite-name" });
  const role = h("select", { id: "invite-role", "data-testid": "invite-role" }, ...ROLES.map(([v, l]) => h("option", { value: v }, l)));
  const ok = await formDialog(
    "invite-dialog",
    "Inviter un opérateur",
    [h("label", { for: "invite-name" }, "Nom"), name, h("label", { for: "invite-role" }, "Rôle"), role],
    () => name.value.trim() !== "",
  );
  return ok ? { name: name.value.trim(), role: role.value as Me["role"] } : null;
}

/// La confirmation n'a de sens que si l'administrateur a comparé l'empreinte
/// avec celle que l'invité lit sur son poste (§10) : il le déclare en cochant.
async function confirmFingerprint(p: PendingKey): Promise<boolean> {
  const box = h("input", { type: "checkbox", id: "compared", required: "", "data-testid": "compared" });
  return formDialog(
    "confirm-dialog",
    `Confirmer la clé de ${p.operator}`,
    [
      h("p", {}, "Comparez cette empreinte, hors bande, avec celle que l'invité a obtenue en enregistrant sa clé :"),
      h("p", { class: "mono hash" }, p.key_fingerprint ?? ""),
      h("label", { for: "compared" }, box, " J'ai comparé l'empreinte avec l'invité : elle est identique."),
    ],
    () => box.checked,
  );
}
