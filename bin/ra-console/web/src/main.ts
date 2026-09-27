// Point d'entrée du frontend de ra-console (docs/WEBUI.md §15 étape 6a).

import { call, isError, type ConsoleInfo, type Me } from "./api";
import { watchIdle } from "./idle";
import { renderLogin } from "./login";
import { idleWarning, renderShell } from "./shell";

async function boot(root: HTMLElement): Promise<void> {
  const described = await call<ConsoleInfo>("GET", "/api/v1/console");
  const info: ConsoleInfo =
    described.body !== null && !isError(described.body)
      ? described.body
      : { environment: "undeclared", version: "?" };

  let stopIdle: (() => void) | null = null;

  const showLogin = (notice?: string): void => {
    stopIdle?.();
    stopIdle = null;
    renderLogin(root, info, showShell, notice);
  };

  const logout = async (notice?: string): Promise<void> => {
    await call("POST", "/api/v1/logout");
    showLogin(notice);
  };

  const showShell = (me: Me): void => {
    renderShell(root, info, me, () => void logout());
    let warning: HTMLElement | null = null;
    stopIdle = watchIdle(
      () => {
        warning ??= idleWarning(root);
      },
      () => void logout("Session verrouillée après 15 minutes d'inactivité : reconnectez-vous avec votre clé."),
    );
    const clearWarning = (): void => {
      warning?.remove();
      warning = null;
    };
    window.addEventListener("keydown", clearWarning);
    window.addEventListener("pointerdown", clearWarning);
  };

  const me = await call<Me>("GET", "/api/v1/me");
  if (me.status === 200 && me.body !== null && !isError(me.body)) {
    showShell(me.body);
  } else {
    showLogin();
  }
}

const root = document.getElementById("app");
if (root !== null) void boot(root);
