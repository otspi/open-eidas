-- Décision O7 révisée (constat A-1) : le challenge d'une action est lié à son
-- corps, SHA-256(domaine ‖ SHA-256(corps) ‖ aléa). L'aléa est conservé ici pour
-- que `operators audit` (ou un tiers qui a le corps figé) recalcule le challenge.
-- NULL pour un challenge émis avant cette migration : tiré au hasard, non lié.
ALTER TABLE action_challenges
    ADD COLUMN IF NOT EXISTS nonce BYTEA;
