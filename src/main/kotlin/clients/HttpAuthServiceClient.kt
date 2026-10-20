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
import kotlinx.serialization.Serializable
import java.time.Instant

class HttpAuthServiceClient(
    private val http: HttpClient,
    private val baseUrl: String,
    private val serviceToken: String,
) : AuthServiceClient {

    // POST /internal/sessions/verify, siehe auth-service/API.md
    // Der Auth-Service muss den Service-Token des Vaults dafür zulassen, bisher kennt er nur den des Gateways (sonst 403 → 502).
    override suspend fun verifySession(token: String, deviceId: String?): VerifiedSession? {
        val body = callUpstream(WHAT) {
            val response = http.post(serviceUrl(baseUrl, "internal", "sessions", "verify")) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                setBody(VerifySessionRequest(token = token, deviceId = deviceId))
            }
            // 401 ist kein Ausfall, sondern die normale Antwort auf einen ungültigen Token.
            if (response.status == HttpStatusCode.Unauthorized) return null
            response.bodyOrThrow<VerifySessionResponse>(WHAT)
        }

        // Die Werte landen später in der DB und in der AAD, deshalb nicht blind übernehmen.
        if (!isValidId(body.userId) || !isValidId(body.sessionId)) throw UpstreamException("$WHAT: invalid ids")
        if (body.deviceId != null && !isValidId(body.deviceId)) throw UpstreamException("$WHAT: invalid device id")

        return VerifiedSession(
            userId = body.userId,
            sessionId = body.sessionId,
            deviceId = body.deviceId,
            expiresAt = Instant.ofEpochSecond(body.expiresAt),
        )
    }

    private companion object {
        const val WHAT = "auth-service sessions/verify"
    }
}

// deviceId = null wird wegen explicitNulls = false (ServiceJson) gar nicht geschickt.
@Serializable
private data class VerifySessionRequest(val token: String, val deviceId: String? = null) {
    // Ohne Login-Token, damit er nie im Log landet.
    override fun toString() = "VerifySessionRequest(deviceId=$deviceId)"
}

@Serializable
private data class VerifySessionResponse(
    val userId: String,
    val sessionId: String,
    val deviceId: String? = null,
    val expiresAt: Long,
)
