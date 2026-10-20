package de.trustylynx.common

import io.ktor.server.application.ApplicationCall

// Diese Header setzt das Gateway, nachdem es Login-Token und Geräte-Signatur geprüft hat.
// TODO: Header-Namen mit dem Gateway abstimmen, die Doku legt sie noch nicht fest.
const val USER_ID_HEADER = "X-User-Id"
const val DEVICE_ID_HEADER = "X-Device-Id"
const val SESSION_ID_HEADER = "X-Session-Id"

/** Tresor-Token, ausgestellt von POST /vault und POST /vault/unlock. Braucht jeder Endpunkt hinter dem Entsperren. */
const val VAULT_TOKEN_HEADER = "X-Vault-Token"

private val ID = Regex("^[A-Za-z0-9._-]{1,128}$")

/** Gleiches Format für userId, deviceId und sessionId, egal ob sie aus einem Header oder vom Auth-Service kommen. */
fun isValidId(value: String): Boolean = ID.matches(value)

/**
 * VORÜBERGEHEND: Ohne X-Device-Id wird dieser Platzhalter gespeichert. Dann ist der Tresor-Token
 * an kein bestimmtes Gerät gebunden (alle Anfragen ohne Header gelten als dasselbe "Gerät").
 * TODO: Wieder entfernen und X-Device-Id Pflicht machen (spätestens mit #8).
 */
const val NO_DEVICE_ID = "no-device"

/** Wer die Anfrage stellt, laut Gateway. Die userId kommt immer von hier, nie aus dem Body. */
class Caller(
    val userId: String,
    val deviceId: String,
    val sessionId: String,
)

/**
 * Liest userId, deviceId und sessionId vom Gateway. Fehlt userId oder sessionId oder ist ein Wert ungültig → [Unauthorized].
 * deviceId ist vorübergehend optional, siehe [NO_DEVICE_ID].
 */
fun ApplicationCall.caller(): Caller = Caller(
    userId = requiredId(USER_ID_HEADER),
    // TODO: Wieder requiredId(DEVICE_ID_HEADER), sobald die Clients die deviceId mitschicken.
    deviceId = optionalId(DEVICE_ID_HEADER) ?: NO_DEVICE_ID,
    sessionId = requiredId(SESSION_ID_HEADER),
)

private fun ApplicationCall.requiredId(header: String): String =
    optionalId(header) ?: throw Unauthorized()

/** Fehlt der Header → null. Ist er da, aber ungültig → [Unauthorized] (kein stilles Ersetzen durch den Platzhalter). */
private fun ApplicationCall.optionalId(header: String): String? {
    val value = request.headers[header] ?: return null
    if (!isValidId(value)) throw Unauthorized()
    return value
}
