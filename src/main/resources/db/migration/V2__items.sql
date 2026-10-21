-- IF NOT EXISTS: Falls items auf dem Server schon von Hand angelegt wurde, bricht der Start nicht ab.

-- Einträge (Passwörter). Kopf und Geheimnis getrennt, beide mit Schicht 2 (C2). Der Server kann sie nicht lesen.
-- item_id erzeugt der Client (z. B. UUID), sie steht in der AAD beider Teile.
CREATE TABLE IF NOT EXISTS items (
    user_id    TEXT    NOT NULL REFERENCES vaults(user_id) ON DELETE CASCADE,
    item_id    TEXT    NOT NULL,
    rev        INTEGER NOT NULL CHECK (rev >= 1),   -- Revision, steht in der AAD, verhindert stilles Überschreiben
    head_c2    BYTEA   NOT NULL,                    -- Titel, URL, Benutzername
    secret_c2  BYTEA   NOT NULL,                    -- Passwort
    PRIMARY KEY (user_id, item_id)
);
