// Verrouillage de session inactive (docs/UI-UX.md §6.3) : avertissement à 14
// minutes, verrouillage à 15 — la session est révoquée côté serveur, et une
// nouvelle authentification FIDO2 est exigée. Indépendant de la durée fixe de
// la session (8 h) : c'est l'inactivité du poste qui est bornée ici.

export const WARN_AFTER_MS = 14 * 60 * 1000;
export const LOCK_AFTER_MS = 15 * 60 * 1000;

const ACTIVITY = ["keydown", "pointerdown", "wheel", "touchstart"] as const;

export function watchIdle(onWarn: () => void, onLock: () => void): () => void {
  let warn = 0;
  let lock = 0;
  const arm = (): void => {
    window.clearTimeout(warn);
    window.clearTimeout(lock);
    warn = window.setTimeout(onWarn, WARN_AFTER_MS);
    lock = window.setTimeout(onLock, LOCK_AFTER_MS);
  };
  for (const event of ACTIVITY) window.addEventListener(event, arm, { passive: true });
  arm();
  return () => {
    window.clearTimeout(warn);
    window.clearTimeout(lock);
    for (const event of ACTIVITY) window.removeEventListener(event, arm);
  };
}
