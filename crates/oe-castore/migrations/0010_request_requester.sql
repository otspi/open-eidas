-- Constat R-3 : le demandeur qui a soumis la CSR (son nom dans la liste des
-- demandeurs de ca-server). Le renouvellement ne révoque que les certificats du
-- même demandeur. Les demandes antérieures portent '' : demandeur historique
-- (secret HMAC unique).
ALTER TABLE enrollment_requests
    ADD COLUMN IF NOT EXISTS requester TEXT NOT NULL DEFAULT '';
