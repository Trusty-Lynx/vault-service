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
| `POST` | `/internal/vault/unlocked` | Nur für den Breach-Service: `204`, wenn der Tresor entsperrt ist, sonst `401 vault_locked` |

`/internal/vault/unlocked` braucht keinen Login-Token, sondern `X-Service-Token` (`SERVICE_TOKEN_BREACH`).
Body: `{userId, sessionId, deviceId, vaultToken}`. userId und sessionId hat der Breach-Service vorher beim Auth-Service geprüft.

Jeder andere Endpoint außer `/health` braucht den Login-Token vom Auth-Service: `Authorization: Bearer <login-token>`.
Der Vault-Service prüft ihn bei jeder Anfrage selbst über `POST /internal/sessions/verify` (#8). Wer anfragt, kommt nur von dort.
Alles außer `/vault`, `/vault/params` und `/vault/unlock` braucht zusätzlich den Tresor-Token im Header `X-Vault-Token`.
Die `itemId` steht im Header `X-Item-Id`, nicht im Pfad (abweichend von der Doku, Entscheid 2026-10-21).
`X-Device-Id` ist vorerst optional.
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
| Auth-Service | `POST /internal/sessions/verify` | Login-Token prüfen, mit dem Gateway-Token (`SERVICE_TOKEN_GATEWAY`) |
| Key-Service | `POST /internal/pepper-hmac` | `h = HMAC(pepper_vault, unlockKey)` für den Tresor-Verifier |
| Crypto-Service 2 (ChaCha20) | `POST /internal/encrypt` | Schicht 2 um wDEK, Kopf und Geheimnis |
| Crypto-Service 2 (ChaCha20) | `POST /internal/decrypt` | Schicht 2 abnehmen |
| Crypto-Service 1 (AES-256-GCM) | `POST /internal/encrypt`, `POST /internal/decrypt` | wie Crypto 2, nur für Einträge mit `alg: "aes"` |

Welcher Crypto-Service einen Eintrag verschlüsselt, wählt der Nutzer pro Eintrag: `PUT /items` mit `alg` = `aes` oder `chacha`
(fehlt es → `chacha`). Beim Entschlüsseln entscheidet das Algorithmus-Byte im C2-Header (`01` AES, `02` ChaCha), eine eigene
DB-Spalte gibt es nicht. `GET /items` liefert `alg` pro Eintrag mit. Der wDEK läuft immer über ChaCha.
Ist ein Crypto-Service nicht erreichbar → `502 { "error": "crypto_unavailable", "reason": "aes" | "chacha" }`.

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

- **Eigener Token beim Auth-Service:** Für `/internal/sessions/verify` nutzen wir den Gateway-Token, weil der Auth-Service
  keinen anderen kennt. Sauberer wäre ein eigener Vault-Token, dafür müsste der Auth-Service zwei Tokens akzeptieren.
- **Geräte-Signatur** (`X-Timestamp`, `X-Device-Sig`) wird nicht geprüft.
- **Vorübergehend:** `X-Device-Id` ist optional (`NO_DEVICE_ID`), und ohne `CORS_ALLOWED_ORIGINS` ist jede Origin erlaubt.
- **Tresor beim Konto löschen:** In der Doku offen, wer das auslöst.
