-- Ohne Guard-Service gibt es keine Geräteverwaltung mehr. Kein Client schickt X-Device-Id, in device_id stand
-- deshalb immer der Platzhalter "no-device". Ein Tresor-Token hängt jetzt nur noch an Nutzer und Login-Session.
-- Bestehende Tresor-Tokens bleiben gültig, sie verlieren nur die Spalte.
ALTER TABLE vault_sessions DROP COLUMN device_id;
