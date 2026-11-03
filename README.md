# vault-service

Tresor für TrustyLynx: Tresor anlegen, mit dem Masterpasswort entsperren, Einträge (Passwörter) speichern und abrufen.
Der Service sieht nie Klartext. Alles kommt vom Client schon verschlüsselt (Schicht 1), der Crypto-Service legt Schicht 2 darum.

Kotlin 2.4 · Ktor 3.6 · PostgreSQL 17 · Java 21

## Endpoints

| Methode | Pfad | Zweck | Wer darf das aufrufen? |
|---|---|---|---|
| `POST` | `/vault` | Tresor einmalig anlegen, liefert den ersten Tresor-Token | Login-Token |
| `GET` | `/vault/params` | Salt und Argon2-Parameter für das Masterpasswort | Login-Token |
| `POST` | `/vault/unlock` | Masterpasswort prüfen (als `unlockKey`), liefert wDEK und Tresor-Token | Login-Token |
| `POST` | `/vault/lock` | Tresor-Token dieses Geräts widerrufen | Login-Token + Tresor-Token |
| `GET` | `/items` | Köpfe aller Einträge (Titel, URL, Benutzer) als C1, ohne Passwörter | Login-Token + Tresor-Token |
| `PUT` | `/items` | Eintrag anlegen (`rev` 1) oder ändern (`rev` + 1) | Login-Token + Tresor-Token |
| `GET` | `/items/secret` | Passwort eines Eintrags als C1 | Login-Token + Tresor-Token |
| `DELETE` | `/items` | Eintrag löschen | Login-Token + Tresor-Token |
| `POST` | `/graphql` | Alles oben noch einmal als GraphQL, siehe unten | wie die REST-Endpoints |
| `GET` | `/health` | `200`, wenn Service und Datenbank laufen, sonst `503` | alle |
| `POST` | `/internal/vault/unlocked` | `204`, wenn der Tresor entsperrt ist, sonst `401 vault_locked` | nur Breach-Service (`X-Service-Token`) |

`/internal/vault/unlocked` braucht keinen Login-Token, sondern `X-Service-Token` (`SERVICE_TOKEN_BREACH`).
Body: `{userId, sessionId, deviceId, vaultToken}`. userId und sessionId hat der Breach-Service vorher beim Auth-Service geprüft.

Jeder andere Endpoint außer `/health` braucht den Login-Token vom Auth-Service: `Authorization: Bearer <login-token>`.
Der Vault-Service prüft ihn bei jeder Anfrage selbst über `POST /internal/sessions/verify` (#8). Wer anfragt, kommt nur von dort.
Alles außer `/vault`, `/vault/params` und `/vault/unlock` braucht zusätzlich den Tresor-Token im Header `X-Vault-Token`.
Die `itemId` steht im Header `X-Item-Id`, nicht im Pfad (abweichend von der Doku, Entscheid 2026-10-21).
`X-Device-Id` ist vorerst optional.
Felder, Fehler und Abläufe: [documentation/api/vault-service](https://github.com/Trusty-Lynx/documentation/tree/main/api/vault-service).

### GraphQL (#36)

`POST /graphql` mit `{ "query": "...", "variables": {...} }`. Schema: `src/main/resources/graphql/schema.graphqls`.
Gleiche Funktionen und Header wie REST, nur die `itemId` ist ein Argument statt `X-Item-Id`:

| GraphQL | REST |
|---|---|
| `query { vaultParams }` | `GET /vault/params` |
| `query { items }` | `GET /items` |
| `query { itemSecret(itemId) }` | `GET /items/secret` |
| `mutation { createVault(input) }` | `POST /vault` |
| `mutation { unlockVault(unlockKey) }` | `POST /vault/unlock` |
| `mutation { lockVault }` | `POST /vault/lock` |
| `mutation { putItem(itemId, input) }` | `PUT /items` |
| `mutation { deleteItem(itemId) }` | `DELETE /items` |

Ohne gültigen Login-Token gibt es wie bei REST `401`. Alle anderen Fehler kommen mit `200` in `errors`, mit demselben Code
wie bei REST in `extensions.code` (dazu `extensions.status` = HTTP-Status, den REST geschickt hätte, bei `rev_conflict` auch `currentRev`).

```bash
curl -X POST localhost:8080/graphql -H "Authorization: Bearer $LOGIN" -H "X-Vault-Token: $VAULT" \
  -H "Content-Type: application/json" -d '{"query":"{ items { id rev alg } }"}'
```

## Struktur

```text
src/main/kotlin/
├── Application.kt     Start: liest die Konfiguration, baut alle Teile, verbindet sie
├── AppConfig.kt       alle Umgebungsvariablen an einer Stelle
├── routes/            HTTP und GraphQL: Request lesen, Eingaben prüfen (Validation.kt), Service aufrufen, antworten
├── services/          Fachlogik (VaultService, ItemService), kennt kein HTTP
├── repositories/      SQL und Datenbank-Setup (Interface + Postgres)
├── clients/           Aufrufe an Key-, Crypto- und Auth-Service
├── models/            Requests/Responses (Dtos.kt), Tabellenzeilen, Fehler, Header-Namen
├── security/          Tresor-Verifier (Argon2id), Tresor-Token, Login-Token-Prüfung, Service-Token, Base64
└── plugins/           Ktor-Einrichtung: JSON, Fehlerantworten, CORS, Request-ID/Logging
src/main/resources/
├── application.yaml
├── logback.xml
├── graphql/           GraphQL-Schema
└── db/migration/      Datenbankschema (Flyway)
src/test/kotlin/       Endpoint-Tests und Fakes, clients/ und security/ wie in main
```

Ein Request läuft immer `routes` → `services` → `repositories` oder `clients`.
Fehler werden als Exception geworfen (`models/ApiException.kt`) und zentral in `plugins/StatusPages.kt` beantwortet.
`module()` baut die echten Teile (Datenbank, HTTP-Client), `configureApp(...)` installiert Plugins und Routen.
So starten die Tests die App mit Fakes. Die Repositories und Clients sind deshalb Interfaces.
Jede Anfrage hat eine `X-Request-Id`. Sie steht in jeder Logzeile und wird an Key- und Crypto-Service weitergereicht.

Andere Services, die hier aufgerufen werden:

| Service | Endpoint | Wofür |
|---|---|---|
| Auth-Service | `POST /internal/sessions/verify` | Login-Token prüfen, mit dem Gateway-Token (`SERVICE_TOKEN_GATEWAY`) |
| Key-Service | `POST /internal/pepper-hmac` | `h = HMAC(pepper_vault, unlockKey)` für den Tresor-Verifier |
| Crypto-Service 2 (ChaCha20) | `POST /internal/encrypt` | Schicht 2 um wDEK, Kopf und Geheimnis |
| Crypto-Service 2 (ChaCha20) | `POST /internal/decrypt` | Schicht 2 abnehmen |
| Crypto-Service 1 (AES-256-GCM) | `POST /internal/encrypt`, `POST /internal/decrypt` | wie Crypto 2, nur für Einträge mit `alg: "aes"`, mit eigenem Token (`SERVICE_TOKEN_AES`) |

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
wird einmalig als Version 1 markiert, danach laufen nur neuere Migrationen (`baselineOnMigrate`, `repositories/Database.kt`).

Läuft Gradle wegen eines Virenscanners mit SSL-Scanning nicht (z. B. Norton), hilft in `~/.gradle/gradle.properties`:
`systemProp.javax.net.ssl.trustStoreType=Windows-ROOT`.

## Tests

```bash
./gradlew test
```

Die Endpoint-Tests laufen ohne Datenbank, Auth-, Key- und Crypto-Service, `src/test/kotlin/Fakes.kt` ersetzt alle.
Die HTTP-Clients werden gegen eine `MockEngine` getestet. Übersprungen wird nichts, Docker braucht es für die Tests nicht.
Dafür testet kein automatischer Test das SQL in `PostgresVaultRepository` und `PostgresItemRepository`, das geht nur
von Hand gegen die Dev-Datenbank (siehe „Lokal starten“).

## Deploy

Ein Push auf den Branch `deploy` baut das Image auf dem Server und startet es neu (`.github/workflows/deploy.yml`).
Die `.env` liegt nur auf dem Server.

## Offen

- **Eigener Token beim Auth-Service:** Für `/internal/sessions/verify` nutzen wir den Gateway-Token, weil der Auth-Service
  keinen anderen kennt. Sauberer wäre ein eigener Vault-Token, dafür müsste der Auth-Service zwei Tokens akzeptieren.
- **Geräte-Signatur** (`X-Timestamp`, `X-Device-Sig`) wird nicht geprüft.
- **Vorübergehend:** `X-Device-Id` ist optional (`NO_DEVICE_ID`), und ohne `CORS_ALLOWED_ORIGINS` ist jede Origin erlaubt.
- **Tresor beim Konto löschen:** In der Doku offen, wer das auslöst.
- **Löschen ohne `rev`:** `DELETE /items` prüft nicht, ob sich der Eintrag inzwischen geändert hat (laut Doku offen).
- **Guard-Ticket beim ChaCha-Service:** Er verlangt für Teil `s` noch ein Ticket. Solange das so ist, gibt `GET /items/secret`
  bei ChaCha-Einträgen `502`.
- **Rate-Limit ist gestrichen,** `TooManyRequests` und der `Retry-After`-Header in `StatusPages` werden nie benutzt.
- **Logger-Name:** Der GraphQL-Fehler-Logger heißt noch `de.trustylynx.api.GraphQL` (altes Paket). Absichtlich so gelassen,
  damit sich die Logzeilen durch den Umbau nicht ändern.
- **Abweichungen von der einheitlichen Struktur:** `security/LoginTokenVerifier` ruft den Auth-Service (`clients/`) auf und
  liest Header aus dem `ApplicationCall`. `routes/GraphQlSchema` nutzt `plugins/AppJson`, damit GraphQL-Eingaben genauso
  gelesen werden wie REST-Bodys. Beides umzubauen hätte die Tests verändert.
- **Doku veraltet:** `documentation/anforderungen/umbau-ohne-guard/vault-service.md` sagt „kein `X-Device-Id`“,
  „`vault_sessions` ohne `device_id`“ und `/items/{itemId}` im Pfad. Der Code macht es nach den späteren Entscheidungen
  anders (Gerät optional gebunden, `itemId` im Header seit 2026-10-21).
