package de.trustylynx.clients

import de.trustylynx.common.IntegrityError
import de.trustylynx.common.SERVICE_TOKEN_HEADER
import de.trustylynx.common.UpstreamException
import de.trustylynx.common.bodyOrThrow
import de.trustylynx.common.callUpstream
import de.trustylynx.common.decodeBase64OrNull
import de.trustylynx.common.serviceUrl
import de.trustylynx.common.toBase64
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

/** Welcher Teil verschlüsselt wird. Geht beim Crypto-Service in die AAD ein. */
enum class CryptoPart(val wire: String) {
    HEAD("h"),
    SECRET("s"),
    DEK("dek"),
}

/**
 * Welcher Crypto-Service Schicht 2 macht. [wire] wie im Key-Service ("aes" / "chacha"),
 * [id] ist das Algorithmus-Byte im C2-Header (Byte 5): 01 = Crypto-Service 1, 02 = Crypto-Service 2.
 */
enum class CryptoAlg(val wire: String, val id: Byte) {
    AES("aes", 0x01),
    CHACHA("chacha", 0x02);

    companion object {
        fun fromWire(wire: String): CryptoAlg? = entries.firstOrNull { it.wire == wire }

        /** Liest das Algorithmus-Byte aus einem gespeicherten C2. Kein TLX2-Paket oder unbekanntes Byte → null. */
        fun ofC2(c2: ByteArray): CryptoAlg? {
            if (c2.size < 6 || !c2.copyOfRange(0, 5).contentEquals(TLX2_V2)) return null
            return entries.firstOrNull { it.id == c2[5] }
        }

        // "TLX2" ‖ Format-Version 02
        private val TLX2_V2 = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02)
    }
}

/** Zugriff auf einen Crypto-Service (Schicht 2). Als Interface, damit Tests einen Fake einsetzen können. */
interface CryptoServiceClient {
    /**
     * Legt Schicht 2 um [c1] und liefert C2 ("TLX2", 36 Byte länger als [c1]).
     * [itemId] ist Pflicht bei [CryptoPart.HEAD] und [CryptoPart.SECRET] und fehlt bei [CryptoPart.DEK].
     */
    suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String? = null): ByteArray

    /**
     * Nimmt Schicht 2 von [c2] ab und liefert C1 (bei [CryptoPart.DEK] den wDEK).
     * Falscher Tag → [de.trustylynx.common.IntegrityError]. Regeln für [itemId] wie bei [encrypt].
     */
    suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String? = null): ByteArray
}

/** HTTP-Client für EINEN Crypto-Service. Beide Services haben dieselben Endpunkte, nur [alg] (und damit der Header) unterscheidet sich. */
class HttpCryptoServiceClient(
    private val http: HttpClient,
    private val baseUrl: String,
    private val serviceToken: String,
    private val alg: CryptoAlg = CryptoAlg.CHACHA,
) : CryptoServiceClient {

    // "TLX2" ‖ Version 02 ‖ Algorithmus-Byte dieses Service. Danach folgt die Key-Version (2 Byte).
    private val c2Prefix = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, alg.id)

    // POST /internal/encrypt, siehe documentation/api/crypto-service/encrypt.md
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

        // Was wir speichern, muss sich später auch wieder öffnen lassen: Format vor dem Speichern prüfen.
        // Falsches Algorithmus-Byte heißt: Wir würden das Paket später an den falschen Service schicken.
        if (c2.size != c1.size + C2_OVERHEAD) throw UpstreamException("$what: expected ${c1.size + C2_OVERHEAD} bytes")
        if (!c2.copyOfRange(0, c2Prefix.size).contentEquals(c2Prefix)) throw UpstreamException("$what: not a TLX2/${alg.wire} package")
        return c2
    }

    // POST /internal/decrypt, siehe documentation/api/crypto-service/decrypt.md
    // TODO: Teil "s" braucht laut Doku ein Guard-Ticket (ticket, sig). Offen, ob das bei uns wegfällt.
    override suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String?): ByteArray {
        requireItemIdRule(part, itemId)
        val what = "crypto-service ${alg.wire} decrypt"

        val body = callUpstream(what) {
            val response = http.post(serviceUrl(baseUrl, "internal", "decrypt")) {
                header(SERVICE_TOKEN_HEADER, serviceToken)
                contentType(ContentType.Application.Json)
                setBody(DecryptRequest(userId = userId, itemId = itemId, part = part.wire, c2 = c2.toBase64()))
            }
            // Falscher Tag ist kein Ausfall, sondern Manipulationsverdacht → nicht als 502 verstecken.
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

    /** Fehlercode aus `{ "error": "…" }`, oder null, wenn der Body keiner ist. */
    private suspend fun HttpResponse.errorCode(): String? = try {
        body<UpstreamError>().error
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        null
    }

    private companion object {
        // 8 Header + 12 Nonce + 16 Tag
        const val C2_OVERHEAD = 36
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
