package de.trustylynx.clients

import de.trustylynx.common.SERVICE_TOKEN_HEADER
import de.trustylynx.common.UpstreamException
import de.trustylynx.common.bodyOrThrow
import de.trustylynx.common.callUpstream
import de.trustylynx.common.isValidId
import de.trustylynx.common.serviceUrl
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import java.time.Instant
import kotlinx.serialization.Serializable

/** Zugriff auf den Auth-Service. Als Interface, damit Tests einen Fake einsetzen können. */
interface AuthServiceClient {
    /**
     * Prüft einen Login-Token über `POST /internal/sessions/verify`.
     * Token unbekannt, abgelaufen oder kaputt → null. Auth nicht erreichbar oder kaputte Antwort → UpstreamException.
     */
    suspend fun verifySession(token: String): VerifiedSession?
}

/** Was der Auth-Service über eine gültige Login-Session sagt. */
class VerifiedSession(
    val userId: String,
    val sessionId: String,
    val expiresAt: Instant,
)

class HttpAuthServiceClient(
    private val http: HttpClient,
    private val baseUrl: String,
    private val serviceToken: String,
) : AuthServiceClient {

    // POST /internal/sessions/verify, siehe auth-service/API.md.
    // [serviceToken] ist der Gateway-Token (SERVICE_TOKEN_GATEWAY): Einen eigenen Token für den Vault kennt der Auth-Service nicht.
    override suspend fun verifySession(token: String): VerifiedSession? {
        val body = callUpstream(WHAT) {
            val response = http.post(serviceUrl(baseUrl, "internal", "sessions", "verify")) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                // Nur {token}: Der Auth-Service lehnt unbekannte Felder (z. B. deviceId) mit 400 ab.
                setBody(VerifySessionRequest(token = token))
            }
            // 401 (unbekannt/abgelaufen) und 400 (Format passt nicht) sind kein Ausfall, sondern "Token ungültig".
            if (response.status == HttpStatusCode.Unauthorized || response.status == HttpStatusCode.BadRequest) return null
            response.bodyOrThrow<VerifySessionResponse>(WHAT)
        }

        // Die Werte landen später in der DB und in der AAD, deshalb nicht blind übernehmen.
        if (!isValidId(body.userId) || !isValidId(body.sessionId)) throw UpstreamException("$WHAT: invalid ids")

        return VerifiedSession(
            userId = body.userId,
            sessionId = body.sessionId,
            expiresAt = Instant.ofEpochSecond(body.expiresAt),
        )
    }

    private companion object {
        const val WHAT = "auth-service sessions/verify"
    }
}

@Serializable
private data class VerifySessionRequest(val token: String) {
    // Ohne Login-Token, damit er nie im Log landet.
    override fun toString() = "VerifySessionRequest"
}

@Serializable
private data class VerifySessionResponse(
    val userId: String,
    val sessionId: String,
    val expiresAt: Long,
)
