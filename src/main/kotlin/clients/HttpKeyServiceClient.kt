package de.trustylynx.clients

import de.trustylynx.common.SERVICE_TOKEN_HEADER
import de.trustylynx.common.UpstreamException
import de.trustylynx.common.bodyOrThrow
import de.trustylynx.common.callUpstream
import de.trustylynx.common.decodeBase64OrNull
import de.trustylynx.common.serviceUrl
import de.trustylynx.common.toBase64
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.Serializable

class HttpKeyServiceClient(
    private val http: HttpClient,
    private val baseUrl: String,
    private val serviceToken: String,
) : KeyServiceClient {

    // POST /internal/pepper-hmac, siehe documentation/api/key-service/pepper-hmac.md
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

    private companion object {
        const val HMAC_LENGTH = 32
    }
}

@Serializable
private data class PepperHmacRequest(val purpose: String, val userId: String, val key: String)

@Serializable
private data class PepperHmacResponse(val h: String)
