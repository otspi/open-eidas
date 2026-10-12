-- Dossiers d'incident de ra-console (docs/WEBUI.md §6) : une structure
-- d'imputabilité, pas un pouvoir. Un dossier regroupe et justifie ; chaque
-- action qu'il désigne passe par les routes existantes, que ca-server juge.
--
-- Table propre à ra-console, comme celles de la migration 0006 : même base,
-- mêmes migrations, mais son seul écrivain est le rôle de la console
-- (sql/ra_console_grants.sql). Les actions consignées dans un dossier et sa
-- clôture viendront avec ces fonctions.
CREATE TABLE IF NOT EXISTS incidents (
    id           UUID        PRIMARY KEY,
    title        TEXT        NOT NULL CHECK (btrim(title) <> ''),
    -- Nom de l'opérateur de la session, comme enrollment_requests.operator.
    opened_by    TEXT        NOT NULL CHECK (opened_by <> ''),
    opened_at    TIMESTAMPTZ NOT NULL,
    state        TEXT        NOT NULL DEFAULT 'OUVERT'
        CHECK (state IN ('OUVERT', 'CLOS')),
    closed_by    TEXT,
    closed_at    TIMESTAMPTZ,
    closing_note TEXT,
    -- Un dossier clos dit qui l'a clos, quand et pourquoi ; un dossier ouvert
    -- ne porte aucune trace de clôture.
    CONSTRAINT closing_imputable CHECK (
        (state = 'OUVERT'
            AND closed_by IS NULL AND closed_at IS NULL AND closing_note IS NULL)
        OR (state = 'CLOS'
            AND closed_by IS NOT NULL AND closed_by <> ''
            AND closed_at IS NOT NULL
            AND closing_note IS NOT NULL AND btrim(closing_note) <> '')
    )
);

CREATE INDEX IF NOT EXISTS incidents_state_idx ON incidents (state, opened_at DESC);
