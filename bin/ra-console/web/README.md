# Frontend de `ra-console`

Conception : [docs/UI-UX.md](../../../docs/UI-UX.md) (spécification, design tokens) et
[docs/WEBUI.md](../../../docs/WEBUI.md) §15 étape 6. TypeScript compilé par esbuild, sans
framework ni dépendance d'exécution : les seules dépendances npm sont de développement
(esbuild, TypeScript, Playwright) et n'entrent jamais dans l'image.

- `src/` : le code du navigateur (typage strict, aucun `innerHTML`).
- `static/` : `index.html` (aucun script ni style en ligne : la CSP l'interdit) et
  `console.css`.
- `dist/` : ce que construit `npm run build`, **versionné** et embarqué dans le binaire
  (`include_bytes!`, `src/web.rs`) : compiler `ra-console` n'exige pas Node. La CI
  vérifie que `dist/` correspond aux sources.
- `e2e/` : parcours Playwright contre une console réelle (`examples/e2e_console.rs`,
  PostgreSQL), avec l'authentificateur WebAuthn virtuel de Chromium.

```bash
npm ci
npm run typecheck
npm run build        # puis committer dist/
OE_CASTORE_TEST_DSN=postgres://postgres:test@localhost:55432/postgres \
  PW_CHANNEL=chrome npx playwright test   # PW_CHANNEL : utiliser le Chrome installé
```
