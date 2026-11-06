package de.trustylynx.clients

import de.trustylynx.models.SERVICE_TOKEN_HEADER
import de.trustylynx.models.UpstreamException
import de.trustylynx.models.isValidId
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import java.time.Instant
import kotlinx.serialization.Serializable

private const val WHAT = "auth-service sessions/verify"

interface AuthServiceClient {
    // null means the token is unknown, expired or broken
    suspend fun verifySession(token: String): VerifiedSession?
}

class VerifiedSession(
    val userId: String,
    val sessionId: String,
    val expiresAt: Instant,
)

// serviceToken is the gateway token, the auth service doesn't know a token of our own
class HttpAuthServiceClient(
    private val http: HttpClient,
    private val baseUrl: String,
    private val serviceToken: String,
) : AuthServiceClient {

    override suspend fun verifySession(token: String): VerifiedSession? {
        val body = callUpstream(WHAT) {
            val response = http.post(serviceUrl(baseUrl, "internal", "sessions", "verify")) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                // only {token}, the auth service rejects unknown fields with 400
                setBody(VerifySessionRequest(token = token))
            }
            // 401 (unknown or expired) and 400 (wrong format) aren't an outage, the token is just invalid
            if (response.status == HttpStatusCode.Unauthorized || response.status == HttpStatusCode.BadRequest) return null
            response.bodyOrThrow<VerifySessionResponse>(WHAT)
        }

        // these values end up in the DB and in the AAD, so don't trust them blindly
        if (!isValidId(body.userId) || !isValidId(body.sessionId)) throw UpstreamException("$WHAT: invalid ids")

        return VerifiedSession(
            userId = body.userId,
            sessionId = body.sessionId,
            expiresAt = Instant.ofEpochSecond(body.expiresAt),
        )
    }
}

@Serializable
private data class VerifySessionRequest(val token: String) {
    // leaves out the login token so it never ends up in a log
    override fun toString() = "VerifySessionRequest"
}

@Serializable
private data class VerifySessionResponse(
    val userId: String,
    val sessionId: String,
    val expiresAt: Long,
)
