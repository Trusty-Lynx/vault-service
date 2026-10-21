package de.trustylynx.common

import io.ktor.server.application.ApplicationCall

// Wer anfragt, steht im Login-Token (Authorization: Bearer …), geprüft vom LoginTokenVerifier beim Auth-Service.
// Die Header hier sagen nur, WAS gemeint ist (Gerät, Tresor-Token, Eintrag), nie WER.

/** Gerät, an das der Tresor-Token gebunden wird. Vorübergehend optional, siehe [NO_DEVICE_ID]. */
const val DEVICE_ID_HEADER = "X-Device-Id"

/** Tresor-Token, ausgestellt von POST /vault und POST /vault/unlock. Braucht jeder Endpunkt hinter dem Entsperren. */
const val VAULT_TOKEN_HEADER = "X-Vault-Token"

/**
 * Welcher Eintrag gemeint ist, bei PUT /items, GET /items/secret und DELETE /items.
 * Abweichung von der Doku (dort im Pfad /items/{itemId}): Entscheid 2026-10-21, alles im Header.
 * Die itemId ist nicht geheim, sie erzeugt der Client (z. B. UUID).
 */
const val ITEM_ID_HEADER = "X-Item-Id"

private val ID = Regex("^[A-Za-z0-9._-]{1,128}$")

/** Gleiches Format für userId, deviceId, sessionId und itemId, egal ob sie aus einem Header oder vom Auth-Service kommen. */
fun isValidId(value: String): Boolean = ID.matches(value)

/**
 * VORÜBERGEHEND: Ohne X-Device-Id wird dieser Platzhalter gespeichert. Dann ist der Tresor-Token
 * an kein bestimmtes Gerät gebunden, aber weiterhin an Nutzer und Login-Session.
 * TODO: Entfernen und X-Device-Id Pflicht machen, sobald die Clients die deviceId immer mitschicken.
 */
const val NO_DEVICE_ID = "no-device"

/** Wer die Anfrage stellt. Kommt nur aus dem geprüften Login-Token (LoginTokenVerifier), nie aus dem Body. */
class Caller(
    val userId: String,
    val deviceId: String,
    val sessionId: String,
)

/** Die itemId aus [ITEM_ID_HEADER]. Fehlt oder ungültig → [BadRequest] (gleiche Zeichen wie die anderen IDs, UUIDs passen). */
fun ApplicationCall.itemId(): String {
    val value = request.headers[ITEM_ID_HEADER] ?: throw BadRequest("missing $ITEM_ID_HEADER")
    if (!isValidId(value)) throw BadRequest("invalid $ITEM_ID_HEADER")
    return value
}
