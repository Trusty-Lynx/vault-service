package de.trustylynx.clients

import de.trustylynx.models.SERVICE_TOKEN_HEADER
import de.trustylynx.models.UpstreamException
import de.trustylynx.security.decodeBase64OrNull
import de.trustylynx.security.toBase64
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.Serializable

private const val HMAC_LENGTH = 32

interface KeyServiceClient {
    // h = HMAC-SHA256(pepper_vault, unlockKey). pepper_vault never leaves the key service, we only get h
    suspend fun pepperHmac(userId: String, unlockKey: ByteArray): ByteArray
}

class HttpKeyServiceClient(
    private val http: HttpClient,
    private val baseUrl: String,
    private val serviceToken: String,
) : KeyServiceClient {

    override suspend fun pepperHmac(userId: String, unlockKey: ByteArray): ByteArray {
        val body = callUpstream("key-service pepper-hmac") {
            http.post(serviceUrl(baseUrl, "internal", "pepper-hmac")) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                setBody(PepperHmacRequest(purpose = "vault", userId = userId, key = unlockKey.toBase64()))
            }.bodyOrThrow<PepperHmacResponse>("key-service pepper-hmac")
        }
        val h = body.h.decodeBase64OrNull() ?: throw UpstreamException("key-service pepper-hmac: invalid Base64")
        if (h.size != HMAC_LENGTH) throw UpstreamException("key-service pepper-hmac: expected $HMAC_LENGTH bytes")
        return h
    }
}

@Serializable
private data class PepperHmacRequest(val purpose: String, val userId: String, val key: String)

@Serializable
private data class PepperHmacResponse(val h: String)
