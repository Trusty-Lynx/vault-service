package de.trustylynx.common

import io.ktor.server.application.ApplicationCall

// Diese Header setzt das Gateway, nachdem es Login-Token und Geräte-Signatur geprüft hat.
// TODO: Header-Namen mit dem Gateway abstimmen, die Doku legt sie noch nicht fest.
const val USER_ID_HEADER = "X-User-Id"
const val DEVICE_ID_HEADER = "X-Device-Id"
const val SESSION_ID_HEADER = "X-Session-Id"

private val ID = Regex("^[A-Za-z0-9._-]{1,128}$")

/** Wer die Anfrage stellt, laut Gateway. Die userId kommt immer von hier, nie aus dem Body. */
class Caller(
    val userId: String,
    val deviceId: String,
    val sessionId: String,
)

/** Liest userId, deviceId und sessionId vom Gateway. Fehlt einer oder ist er ungültig → [Unauthorized]. */
fun ApplicationCall.caller(): Caller = Caller(
    userId = requiredId(USER_ID_HEADER),
    deviceId = requiredId(DEVICE_ID_HEADER),
    sessionId = requiredId(SESSION_ID_HEADER),
)

private fun ApplicationCall.requiredId(header: String): String {
    val value = request.headers[header]
    if (value == null || !ID.matches(value)) throw Unauthorized()
    return value
}
