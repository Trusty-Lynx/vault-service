# vault-service

Tresor für TrustyLynx: Tresor anlegen, mit dem Masterpasswort entsperren, Einträge (Passwörter) speichern und abrufen.
Der Service sieht nie Klartext. Alles kommt vom Client schon verschlüsselt (Schicht 1), der Crypto-Service legt Schicht 2 darum.

Kotlin 2.4 · Ktor 3.6 · PostgreSQL 17 · Java 21

## Endpoints

| Methode | Pfad | Zweck |
|---|---|---|
| `POST` | `/vault` | Tresor einmalig anlegen, liefert den ersten Tresor-Token |
| `GET` | `/vault/params` | Salt und Argon2-Parameter für das Masterpasswort |
| `POST` | `/vault/unlock` | Masterpasswort prüfen (als `unlockKey`), liefert wDEK und Tresor-Token |
| `POST` | `/vault/lock` | Tresor-Token dieses Geräts widerrufen |
| `GET` | `/items` | Köpfe aller Einträge (Titel, URL, Benutzer) als C1, ohne Passwörter |
| `PUT` | `/items` | Eintrag anlegen (`rev` 1) oder ändern (`rev` + 1) |
| `GET` | `/items/secret` | Passwort eines Eintrags als C1 |
| `DELETE` | `/items` | Eintrag löschen |
| `GET` | `/health` | `200`, wenn Service und Datenbank laufen, sonst `503` |

Alles außer `/vault`, `/vault/params` und `/vault/unlock` braucht den Tresor-Token im Header `X-Vault-Token`.
Die `itemId` steht im Header `X-Item-Id`, nicht im Pfad (abweichend von der Doku, Entscheid 2026-10-21).
Wer anfragt, steht vorerst in `X-User-Id`, `X-Session-Id` und optional `X-Device-Id` (Platzhalter bis #8).
Felder, Fehler und Abläufe: [documentation/api/vault-service](https://github.com/Trusty-Lynx/documentation/tree/main/api/vault-service).

## Struktur

```text
src/main/kotlin/
├── Application.kt   Einstieg: baut alle Teile und verdrahtet sie
├── AppConfig.kt     alle Umgebungsvariablen an einer Stelle
├── api/             Routen und Request-/Response-Klassen (Dtos.kt)
├── validation/      Requests prüfen und in Domain-Objekte übersetzen
├── domain/          Use Cases (VaultService, ItemService) und Modelle (Vault.kt, Item.kt)
├── persistence/     Repositories (Interface + Postgres)
├── clients/         Aufrufe an andere Services (Key-, Crypto-, Auth-Service)
├── security/        Tresor-Verifier (Argon2id), Tresor-Token, Login-Token-Prüfung (#8)
└── common/          gleich in allen Services: Fehler, JSON, Env, DB, HTTP-Client, Health, Request-ID, CORS
src/main/resources/db/migration/   Datenbankschema (Flyway)
```

Ein Request läuft immer `api` → `validation` → `domain` → `persistence`/`clients`.
Fehler werden als Exception geworfen (`common/ApiException.kt`) und zentral in `common/StatusPages.kt` beantwortet.
Jede Anfrage hat eine `X-Request-Id`. Sie steht in jeder Logzeile und wird an Key- und Crypto-Service weitergereicht.

Andere Services, die hier aufgerufen werden:

| Service | Endpoint | Wofür |
|---|---|---|
| Key-Service | `POST /internal/pepper-hmac` | `h = HMAC(pepper_vault, unlockKey)` für den Tresor-Verifier |
| Crypto-Service 2 (ChaCha20) | `POST /internal/encrypt` | Schicht 2 um wDEK, Kopf und Geheimnis |
| Crypto-Service 2 (ChaCha20) | `POST /internal/decrypt` | Schicht 2 abnehmen |

## Lokal starten

```bash
docker compose -f docker-compose.dev.yml up -d   # Postgres auf localhost:5435
./gradlew run -Pdevelopment                      # Port 8080, Dev-Defaults aus AppConfig
```

Ohne `-Pdevelopment` müssen alle Pflichtvariablen gesetzt sein. Welche das sind, steht in `.env.example`.
Das Schema legt Flyway beim Start an. Eine DB, die `vaults` und `vault_sessions` schon ohne Flyway hatte,
wird einmalig als Version 1 markiert, danach laufen nur neuere Migrationen (`baselineOnMigrate`, `common/Database.kt`).

Läuft Gradle wegen eines Virenscanners mit SSL-Scanning nicht (z. B. Norton), hilft in `~/.gradle/gradle.properties`:
`systemProp.javax.net.ssl.trustStoreType=Windows-ROOT`.

## Tests

```bash
./gradlew test
```

Die Endpoint-Tests laufen ohne Datenbank, Key- und Crypto-Service, `src/test/kotlin/Fakes.kt` ersetzt alle drei.
Die HTTP-Clients werden gegen eine `MockEngine` getestet.

## Deploy

Ein Push auf den Branch `deploy` baut das Image auf dem Server und startet es neu (`.github/workflows/deploy.yml`).
Die `.env` liegt nur auf dem Server.

## Offen

- **Login-Token prüfen (#8):** `security/LoginTokenVerifier.kt` ist fertig, aber noch nicht in den Routen.
  Erst einhängen, wenn der Auth-Service den Vault als Aufrufer von `/internal/sessions/verify` zulässt.
  Dann in den Routen `call.caller()` ersetzen und `X-User-Id` / `X-Session-Id` fallen weg.
- **Geheimnis abrufen (#18):** Der ChaCha-Service verlangt bei `decrypt` mit Teil `s` noch ein Guard-Ticket und
  antwortet sonst `403` (bei uns `502`). Ohne Guard muss die Prüfung dort entfallen.
- **Vorübergehend:** `X-Device-Id` ist optional (`NO_DEVICE_ID`), und ohne `CORS_ALLOWED_ORIGINS` ist jede Origin erlaubt.
- **Tresor beim Konto löschen:** In der Doku offen, wer das auslöst.
