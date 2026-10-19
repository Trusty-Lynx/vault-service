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

class HttpCryptoServiceClient(
    private val http: HttpClient,
    private val baseUrl: String,
    private val serviceToken: String,
) : CryptoServiceClient {

    // POST /internal/encrypt, siehe documentation/api/crypto-service/encrypt.md
    override suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String?): ByteArray {
        require((part == CryptoPart.DEK) == (itemId == null)) { "itemId is required for h/s and forbidden for dek" }

        val body = callUpstream("crypto-service encrypt") {
            http.post(serviceUrl(baseUrl, "internal", "encrypt")) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                setBody(EncryptRequest(userId = userId, itemId = itemId, part = part.wire, c1 = c1.toBase64()))
            }.bodyOrThrow<EncryptResponse>("crypto-service encrypt")
        }
        val c2 = body.c2.decodeBase64OrNull() ?: throw UpstreamException("crypto-service encrypt: invalid Base64")

        // Was wir speichern, muss sich später auch wieder öffnen lassen: Format vor dem Speichern prüfen.
        if (c2.size != c1.size + C2_OVERHEAD) throw UpstreamException("crypto-service encrypt: expected ${c1.size + C2_OVERHEAD} bytes")
        if (!c2.copyOfRange(0, C2_PREFIX.size).contentEquals(C2_PREFIX)) throw UpstreamException("crypto-service encrypt: not a TLX2/AES package")
        return c2
    }

    private companion object {
        // 8 Header + 12 Nonce + 16 Tag
        const val C2_OVERHEAD = 36

        // "TLX2" ‖ Version 02 ‖ Algorithmus 01 (AES-256-GCM). Danach folgt die Key-Version (2 Byte).
        val C2_PREFIX = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, 0x01)
    }
}

@Serializable
private data class EncryptRequest(val userId: String, val itemId: String?, val part: String, val c1: String)

@Serializable
private data class EncryptResponse(val c2: String)
