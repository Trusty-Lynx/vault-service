package de.trustylynx.security

import de.trustylynx.clients.AuthServiceClient
import de.trustylynx.common.Caller
import de.trustylynx.common.DEVICE_ID_HEADER
import de.trustylynx.common.NO_DEVICE_ID
import de.trustylynx.common.Unauthorized
import de.trustylynx.common.isValidId
import io.ktor.http.HttpHeaders
import io.ktor.server.application.ApplicationCall

/**
 * Prüft den Login-Token selbst beim Auth-Service (Issue #8, Variante A), statt den Headern vom Gateway zu glauben.
 * Der [Caller] kommt danach nur aus der Antwort des Auth-Service, nie aus X-User-Id / X-Session-Id.
 *
 * NOCH NICHT IN DEN ROUTEN: Erst einhängen, wenn der Auth-Service den Vault als Aufrufer von
 * /internal/sessions/verify zulässt. Dann in den Routen `call.caller()` durch `loginTokens.verify(call)` ersetzen.
 */
class LoginTokenVerifier(private val auth: AuthServiceClient) {

    /** Fehlender, kaputter oder ungültiger Login-Token → [Unauthorized]. Auth nicht erreichbar → UpstreamException (502). */
    suspend fun verify(call: ApplicationCall): Caller {
        val token = call.bearerToken() ?: throw Unauthorized()
        // VORÜBERGEHEND optional, solange die Clients die deviceId noch nicht immer schicken (siehe NO_DEVICE_ID).
        val deviceId = call.request.headers[DEVICE_ID_HEADER]?.also { if (!isValidId(it)) throw Unauthorized() }

        val session = auth.verifySession(token, deviceId) ?: throw Unauthorized()
        // Prüft der Auth-Service eigentlich schon, aber die Bindung an das Gerät ist zu wichtig, um sich nur darauf zu verlassen.
        if (deviceId != null && session.deviceId != null && session.deviceId != deviceId) throw Unauthorized()

        return Caller(
            userId = session.userId,
            deviceId = deviceId ?: NO_DEVICE_ID,
            sessionId = session.sessionId,
        )
    }

    private companion object {
        // Gleiche Grenze wie im Auth-Service, längere Tokens lehnt er mit 400 ab.
        const val MAX_TOKEN_LENGTH = 512
        const val BEARER = "Bearer "

        /** `Authorization: Bearer <token>`. Fehlt oder passt das Format nicht → null, ohne den Auth-Service zu fragen. */
        fun ApplicationCall.bearerToken(): String? {
            val header = request.headers[HttpHeaders.Authorization] ?: return null
            if (!header.startsWith(BEARER, ignoreCase = true)) return null
            val token = header.substring(BEARER.length).trim()
            if (token.isEmpty() || token.length > MAX_TOKEN_LENGTH || token.any { it.isWhitespace() }) return null
            return token
        }
    }
}
