package de.trustylynx.clients

import de.trustylynx.models.IntegrityError
import de.trustylynx.models.SERVICE_TOKEN_HEADER
import de.trustylynx.models.UpstreamException
import de.trustylynx.security.decodeBase64OrNull
import de.trustylynx.security.toBase64
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.Serializable

// 8 header + 12 nonce + 16 tag
private const val C2_OVERHEAD = 36

// part of the AAD in the crypto service
enum class CryptoPart(val wire: String) {
    HEAD("h"),
    SECRET("s"),
    DEK("dek"),
}

// id is the algorithm byte in the C2 header (byte 5): 01 = AES service, 02 = ChaCha service
enum class CryptoAlg(val wire: String, val id: Byte) {
    AES("aes", 0x01),
    CHACHA("chacha", 0x02);

    companion object {
        fun fromWire(wire: String): CryptoAlg? = entries.firstOrNull { it.wire == wire }

        // null if it's not a TLX2 package or the algorithm byte is unknown
        fun ofC2(c2: ByteArray): CryptoAlg? {
            if (c2.size < 6 || !c2.copyOfRange(0, 5).contentEquals(TLX2_V2)) return null
            return entries.firstOrNull { it.id == c2[5] }
        }

        // "TLX2" + format version 02
        private val TLX2_V2 = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02)
    }
}

// itemId is required for HEAD and SECRET and must be null for DEK
interface CryptoServiceClient {
    suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String? = null): ByteArray

    suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String? = null): ByteArray
}

// both crypto services have the same endpoints, only alg (and so the C2 header) differs
class HttpCryptoServiceClient(
    private val http: HttpClient,
    private val baseUrl: String,
    private val serviceToken: String,
    private val alg: CryptoAlg,
) : CryptoServiceClient {

    // "TLX2" + version 02 + algorithm byte of this service, the key version (2 bytes) comes after
    private val c2Prefix = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, alg.id)

    override suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String?): ByteArray {
        requireItemIdRule(part, itemId)
        val what = "crypto-service ${alg.wire} encrypt"

        val body = callUpstream(what) {
            http.post(serviceUrl(baseUrl, "internal", "encrypt")) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                setBody(EncryptRequest(userId = userId, itemId = itemId, part = part.wire, c1 = c1.toBase64()))
            }.bodyOrThrow<EncryptResponse>(what)
        }
        val c2 = body.c2.decodeBase64OrNull() ?: throw UpstreamException("$what: invalid Base64")

        // check the format before we store it, we have to be able to open it later.
        // A wrong algorithm byte would send the package to the wrong service on decrypt
        if (c2.size != c1.size + C2_OVERHEAD) throw UpstreamException("$what: expected ${c1.size + C2_OVERHEAD} bytes")
        if (!c2.copyOfRange(0, c2Prefix.size).contentEquals(c2Prefix)) throw UpstreamException("$what: not a TLX2/${alg.wire} package")
        return c2
    }

    // TODO: the docs still want a guard ticket (ticket, sig) for part "s", not clear yet if that goes away for us
    override suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String?): ByteArray {
        requireItemIdRule(part, itemId)
        val what = "crypto-service ${alg.wire} decrypt"

        val body = callUpstream(what) {
            val response = http.post(serviceUrl(baseUrl, "internal", "decrypt")) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                setBody(DecryptRequest(userId = userId, itemId = itemId, part = part.wire, c2 = c2.toBase64()))
            }
            // a wrong tag means possible tampering, not an outage, so don't hide it behind a 502
            if (response.status == HttpStatusCode.InternalServerError && response.errorCode() == "integrity_error") {
                throw IntegrityError()
            }
            response.bodyOrThrow<DecryptResponse>(what)
        }
        val c1 = body.c1.decodeBase64OrNull() ?: throw UpstreamException("$what: invalid Base64")
        if (c1.size != c2.size - C2_OVERHEAD) throw UpstreamException("$what: expected ${c2.size - C2_OVERHEAD} bytes")
        return c1
    }

    private fun requireItemIdRule(part: CryptoPart, itemId: String?) =
        require((part == CryptoPart.DEK) == (itemId == null)) { "itemId is required for h/s and forbidden for dek" }

    // null if the body isn't { "error": "..." }
    private suspend fun HttpResponse.errorCode(): String? = try {
        body<UpstreamError>().error
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        null
    }
}

@Serializable
private data class EncryptRequest(val userId: String, val itemId: String?, val part: String, val c1: String)

@Serializable
private data class EncryptResponse(val c2: String)

@Serializable
private data class DecryptRequest(val userId: String, val itemId: String?, val part: String, val c2: String)

@Serializable
private data class DecryptResponse(val c1: String)

@Serializable
private data class UpstreamError(val error: String)
