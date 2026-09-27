-- Droits du rôle applicatif de ra-console sur les tables de ca-server
-- (docs/WEBUI.md §16). Règle unique : lecture seule sur tout ce qui
-- appartient à ca-server. Aucun INSERT, UPDATE ni DELETE : c'est ce qui
-- ferme la faille où une console compromise écrivait une approbation en
-- base et obtenait l'émission d'un certificat.
--
-- Le rôle est créé sans droit de connexion : le déploiement lui donne son
-- mot de passe (Helm). Idempotent, rejouable à chaque déploiement.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openeidas_ra_console') THEN
        CREATE ROLE openeidas_ra_console NOLOGIN;
    END IF;
END
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM openeidas_ra_console;

GRANT SELECT ON
    enrollment_requests,
    certificates,
    operators,
    webauthn_credentials,
    pending_credentials,
    decision_evidence,
    -- Les actions figées (corps, empreinte, seuil, échéance) : la salle
    -- d'attente des actions à plusieurs signatures (docs/WEBUI.md §8) les lit
    -- ici plutôt que d'en tenir une copie. Aucun secret n'y figure : le jeton
    -- d'une invitation n'est rendu que dans le résultat de l'exécution.
    actions
TO openeidas_ra_console;

-- Pour les clés étrangères des tables propres à ra-console.
GRANT REFERENCES ON operators, webauthn_credentials TO openeidas_ra_console;

-- Ses propres tables (migration 0006) : ce qui ne donne aucun pouvoir sur la PKI.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    webauthn_challenges,
    sessions,
    login_counters
TO openeidas_ra_console;

-- Aucun droit, même en lecture : operator_invites (hachés de jetons),
-- actions, action_challenges, authorities, crls.
