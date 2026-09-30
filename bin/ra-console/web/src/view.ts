// Une vue de la zone de travail : son élément, et de quoi la quitter proprement
// (raccourcis clavier, minuteries).
export interface View {
  element: HTMLElement;
  dispose: () => void;
}
