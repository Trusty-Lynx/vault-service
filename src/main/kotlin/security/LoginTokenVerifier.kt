package de.trustylynx.security

import de.trustylynx.clients.AuthServiceClient
import de.trustylynx.models.Caller
import de.trustylynx.models.Unauthorized
import io.ktor.http.HttpHeaders
import io.ktor.server.application.ApplicationCall

// same limit as the auth service, it rejects longer tokens with 400
private const val MAX_TOKEN_LENGTH = 512
private const val BEARER = "Bearer "

// Asks the auth service on every request. userId and sessionId only come from its answer, never from headers
// or the body. Once the login session ends, verify fails and so the vault is locked as well.
class LoginTokenVerifier(private val auth: AuthServiceClient) {

    suspend fun verify(call: ApplicationCall): Caller {
        val token = call.bearerToken() ?: throw Unauthorized()
        val session = auth.verifySession(token) ?: throw Unauthorized()

        return Caller(
            userId = session.userId,
            sessionId = session.sessionId,
        )
    }
}

// null if the header is missing or malformed, then we don't even ask the auth service
private fun ApplicationCall.bearerToken(): String? {
    val header = request.headers[HttpHeaders.Authorization] ?: return null
    if (!header.startsWith(BEARER, ignoreCase = true)) return null
    val token = header.substring(BEARER.length).trim()
    if (token.isEmpty() || token.length > MAX_TOKEN_LENGTH || token.any { it.isWhitespace() }) return null
    return token
}
