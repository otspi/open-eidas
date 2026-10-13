-- Suite des dossiers d'incident de ra-console (docs/WEBUI.md §6, migration
-- 0008) : ce qu'on y consigne, et la preuve de leur clôture. Mêmes principes :
-- des tables propres à la console, sans pouvoir sur la PKI, dont les invariants
-- sont portés par la base.

-- Ce qu'un opérateur consigne dans un dossier ouvert : une note, ou la
-- référence d'une action figée par ca-server (une révocation, par exemple).
-- Le dossier ne déclenche rien : il désigne une action qui existe, avec
-- l'empreinte de son corps, celle que le journal de ca-server porte aussi.
CREATE TABLE IF NOT EXISTS incident_actions (
    id          UUID        PRIMARY KEY,
    incident_id UUID        NOT NULL REFERENCES incidents(id),
    at          TIMESTAMPTZ NOT NULL,
    operator    TEXT        NOT NULL CHECK (operator <> ''),
    kind        TEXT        NOT NULL CHECK (kind IN ('note', 'action_liee')),
    action_id   UUID        REFERENCES actions(id),
    body_hash   BYTEA,
    detail      TEXT        NOT NULL DEFAULT '',
    CONSTRAINT action_reference CHECK (
        (kind = 'note'
            AND action_id IS NULL AND body_hash IS NULL AND btrim(detail) <> '')
        OR (kind = 'action_liee'
            AND action_id IS NOT NULL AND body_hash IS NOT NULL)
    ),
    -- Une action n'est rattachée qu'une fois à un même dossier.
    UNIQUE (incident_id, action_id)
);

CREATE INDEX IF NOT EXISTS incident_actions_incident_idx ON incident_actions (incident_id, at);

-- Rien ne s'ajoute à un dossier clos. Le verrou partagé sur le dossier ordonne
-- cette écriture par rapport à une clôture concurrente.
CREATE OR REPLACE FUNCTION incident_actions_only_while_open() RETURNS trigger AS $$
BEGIN
    PERFORM 1 FROM incidents WHERE id = NEW.incident_id AND state = 'OUVERT' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'dossier d''incident clos ou inconnu'
            USING ERRCODE = '23514', CONSTRAINT = 'incident_open';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS incident_actions_only_while_open ON incident_actions;
CREATE TRIGGER incident_actions_only_while_open
    BEFORE INSERT ON incident_actions
    FOR EACH ROW EXECUTE FUNCTION incident_actions_only_while_open();

-- La preuve d'une clôture : l'assertion WebAuthn de l'opérateur, vérifiée par
-- ra-console, sur le corps exact qui lui a été montré. Même forme que
-- decision_evidence côté ca-server, pour qu'un tiers puisse la revérifier.
CREATE TABLE IF NOT EXISTS incident_closures (
    incident_id        UUID        PRIMARY KEY REFERENCES incidents(id),
    operator_id        UUID        NOT NULL REFERENCES operators(id),
    credential_id      TEXT        NOT NULL REFERENCES webauthn_credentials(credential_id),
    -- Le corps figé, tel qu'il a été haché et affiché, et le challenge signé.
    body               TEXT        NOT NULL,
    body_hash          BYTEA       NOT NULL,
    challenge          BYTEA       NOT NULL,
    authenticator_data BYTEA       NOT NULL,
    client_data_json   BYTEA       NOT NULL,
    signature          BYTEA       NOT NULL,
    verified_at        TIMESTAMPTZ NOT NULL
);

-- Un dossier ne se clôt pas sans sa preuve, et un dossier clos ne change plus.
CREATE OR REPLACE FUNCTION incidents_closing_rules() RETURNS trigger AS $$
BEGIN
    IF OLD.state = 'CLOS' THEN
        RAISE EXCEPTION 'un dossier d''incident clos ne se modifie plus'
            USING ERRCODE = '23514', CONSTRAINT = 'incident_closed_is_final';
    END IF;
    IF NEW.state = 'CLOS'
        AND NOT EXISTS (SELECT 1 FROM incident_closures WHERE incident_id = NEW.id) THEN
        RAISE EXCEPTION 'clôture sans preuve'
            USING ERRCODE = '23514', CONSTRAINT = 'incident_closing_evidence';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS incidents_closing_rules ON incidents;
CREATE TRIGGER incidents_closing_rules
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION incidents_closing_rules();

-- Le challenge de l'assertion de clôture est celui de la console (ra-console
-- la vérifie elle-même) : un quatrième type, opérateur obligatoire comme pour
-- 'register' et 'action' (contrainte challenge_operator_known).
ALTER TABLE webauthn_challenges DROP CONSTRAINT IF EXISTS webauthn_challenges_kind_check;
ALTER TABLE webauthn_challenges ADD CONSTRAINT webauthn_challenges_kind_check
    CHECK (kind IN ('register', 'login', 'action', 'incident_close'));
