-- Schema der vault-db, Stand vor Flyway. Flyway führt das beim Start aus (common/Database.kt, migrateDatabase).
-- Auf DBs, die vaults und vault_sessions schon von Hand hatten, wird V1 übersprungen (baselineOnMigrate).
-- Bereits ausgeführte Migrationen nie ändern, sondern eine neue Datei V<n+1>__… anlegen.

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
