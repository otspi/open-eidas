-- Constat C-1 de l'audit du 2026-09-25 (EN 319 411-1 CSS-6.3.9-12/-13,
-- CSS-6.3.10-01) : rien ne permettait de révoquer une autorité, et la racine
-- ne publiait aucune ARL. Reproduit exactement le patron déjà en place pour
-- les certificats d'entité finale (colonnes revoked_at/revocation_reason,
-- table crls) plutôt que d'en inventer un nouveau.

ALTER TABLE authorities
    ADD COLUMN IF NOT EXISTS revoked_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revocation_reason INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS arls (
    number      BIGINT PRIMARY KEY,
    der         BYTEA       NOT NULL,
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS arl_number_seq START WITH 1;
