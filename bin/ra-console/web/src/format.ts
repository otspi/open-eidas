// Formats d'affichage de docs/UI-UX.md §4.2 : dates ISO 8601 en UTC,
// empreintes groupées, identifiants en monospace (le style s'en charge).

export function utc(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

/// Empreinte hexadécimale groupée par 8 caractères, lisible à voix haute.
export function groupedHash(hex: string): string {
  return (hex.match(/.{1,8}/g) ?? []).join(" ");
}
