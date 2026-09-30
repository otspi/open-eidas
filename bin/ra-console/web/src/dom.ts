// Construction du DOM sans `innerHTML` : tout contenu venu de l'API (noms,
// motifs, corps à signer) est inséré comme texte, jamais interprété. C'est ce
// qui ferme l'injection de HTML, en plus de la CSP (docs/UI-UX.md §6.3).

type Child = Node | string | null | undefined | false;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    el.setAttribute(name, value);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    el.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return el;
}

export function replace(target: Element, ...children: Node[]): void {
  target.replaceChildren(...children);
}
