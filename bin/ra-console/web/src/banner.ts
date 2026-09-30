// Bannière d'environnement (docs/UI-UX.md §1 principe 4, §2.1) : PRODUCTION
// en rouge, toujours visible, sur tous les écrans y compris la connexion.

import type { ConsoleInfo } from "./api";
import { h } from "./dom";

const LABELS: Record<ConsoleInfo["environment"], string> = {
  production: "PRODUCTION",
  staging: "STAGING",
  demo: "DÉMONSTRATION",
  undeclared: "ENVIRONNEMENT NON DÉCLARÉ",
};

export function banner(info: ConsoleInfo): HTMLElement {
  return h(
    "div",
    { class: `env-banner env-${info.environment}`, role: "status", "data-testid": "env-banner" },
    LABELS[info.environment],
  );
}
