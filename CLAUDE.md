# Open eIDAS — consignes pour Claude

**Au début de chaque session, lire [PROGRESSION.md](PROGRESSION.md)** : c'est le passage de
relais du travail en cours (état de la pile de PR, ordre de merge et procédure de rebase,
décisions déjà prises avec l'utilisateur, pièges rencontrés, prochaine étape). Le tenir à jour
à chaque PR ouverte ou mergée. Il est local et non suivi, comme ce fichier : ne jamais le `git add`.

**Puis lire [TODO.md](TODO.md)** : c'est l'inventaire de ce
qui reste ouvert (tranches à faire, décisions en attente, vérifications, docs à
mettre à jour). Le tenir à jour à chaque tranche mergée : cocher, ajouter,
retirer. Le détail et les justifications sont dans `docs/WEBUI.md` (renvois `§N`).

## Repères utiles

- **Dépôt** : `otspi/open-eidas` (l'ancien nom `open-eidas/open-eidas` redirige, mais `gh pr create` doit recevoir `-R otspi/open-eidas --head <branche>`).
- **Branches et PR** : on part de `dev`, PR vers `dev`. `main` ne suit que la production certifiée (vide aujourd'hui). Titre de PR au format conventionnel (un check le vérifie), messages de commit en français.
- **Règle de merge** : `dev` exige 1 review approuvante et des checks à jour. Un merge `--admin` ne se fait que sur demande explicite de l'utilisateur ; ne jamais en programmer un sans lui. **Autorisation du 2026-09-21** (l'utilisateur est seul sur le dépôt) : merge `--admin` en squash de la pile #27, #31, #19, #20, #23, #21, #22, #24, #25, #26, #28, #29, #30 dans cet ordre (voir PROGRESSION.md §2), checks verts requis avant chaque merge. Ne couvre ni #5 ni #32, ni les PR futures.
- **Pile de PR** : après un squash-merge, rebaser la PR suivante avec `git rebase --onto origin/dev <ancienne tête de la PR mergée>`, pousser avec `--force-with-lease` (branches de travail uniquement), et rebrancher via l'API REST : `gh api -X PATCH repos/otspi/open-eidas/pulls/N -f base=dev`. `gh pr edit` échoue (erreur GraphQL « Projects classic »).
- **Tests PostgreSQL** : gardés par `OE_CASTORE_TEST_DSN`. Sans elle ils **s'ignorent en restant verts**. En local : `docker run -d -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:17-alpine`, puis `OE_CASTORE_TEST_DSN=postgres://postgres:test@localhost:55432/postgres cargo test -p oe-castore -p oe-actions -p ca-server --features oe-castore/postgres`.
- **Avant de déclarer une tranche prête** : `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo audit --ignore RUSTSEC-2023-0071`. Pour un contrôle de sécurité, vérifier par mutation que le test échoue quand on retire le contrôle.
- **Documents générés ou déclaratifs** : `docs/CONFORMITE-ETSI.md` est généré par `oe_conformance::system_matrix()` (ne pas l'éditer à la main) ; `docs/CPS.md` ne décrit que du code réellement en service.
- **Ne pas toucher** à `docs/mockups/` ni à `docs/UI-UX.md` sans accord : c'est le travail d'antigravity.
