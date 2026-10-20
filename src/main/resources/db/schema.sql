-- Schema der vault-db. Einmal von Hand ausführen (z. B. in DataGrip).

-- Ein Tresor pro Nutzer. user_id kommt aus dem Login-Token (auth-service), deshalb kein Fremdschlüssel.
CREATE TABLE vaults (
    user_id         TEXT  PRIMARY KEY,
    salt_vault      BYTEA NOT NULL,     -- 16 Byte, vom Client gewürfelt
    kdf_vault       TEXT  NOT NULL,     -- Argon2-Parameter als JSON
    salt_s_vault    BYTEA NOT NULL,     -- 16 Byte, vom Vault-Service gewürfelt
    vault_verifier  BYTEA NOT NULL,     -- 32 Byte, Argon2id(HMAC(pepper_vault, unlockKey), salt_s_vault)
    wdek_c2         BYTEA NOT NULL,     -- 98 Byte, wDEK mit Schicht 2
    wdek_c2_prev    BYTEA               -- Version vor dem letzten Masterpasswort-Wechsel
);

-- Tresor-Tokens (entsperrte Tresore). Gespeichert wird nur der SHA-256-Hash, nie der Token selbst.
CREATE TABLE vault_sessions (
    token_hash  BYTEA       PRIMARY KEY,
    user_id     TEXT        NOT NULL REFERENCES vaults(user_id) ON DELETE CASCADE,
    device_id   TEXT        NOT NULL,
    session_id  TEXT        NOT NULL,   -- Login-Session, an die der Tresor-Token gebunden ist
    expires_at  TIMESTAMPTZ NOT NULL    -- 15 min nach der letzten Tresor-Anfrage
);

-- Einträge (Passwörter). Kopf und Geheimnis getrennt, beide mit Schicht 2 (C2). Der Server kann sie nicht lesen.
-- item_id erzeugt der Client (z. B. UUID), sie steht in der AAD beider Teile.
CREATE TABLE items (
    user_id    TEXT    NOT NULL REFERENCES vaults(user_id) ON DELETE CASCADE,
    item_id    TEXT    NOT NULL,
    rev        INTEGER NOT NULL CHECK (rev >= 1),   -- Revision, steht in der AAD, verhindert stilles Überschreiben
    head_c2    BYTEA   NOT NULL,                    -- Titel, URL, Benutzername
    secret_c2  BYTEA   NOT NULL,                    -- Passwort
    PRIMARY KEY (user_id, item_id)
);
