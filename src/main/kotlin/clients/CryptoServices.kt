package de.trustylynx.clients

import de.trustylynx.common.CryptoUnavailable
import de.trustylynx.common.IntegrityError
import de.trustylynx.common.UpstreamException

/**
 * Beide Crypto-Services für Einträge. Der Nutzer wählt pro Eintrag, wer Schicht 2 macht (Entscheid 2026-10-29).
 * Verschlüsseln: an den gewählten Service. Entschlüsseln: an den Service aus dem Algorithmus-Byte des gespeicherten C2,
 * deshalb braucht die DB keine eigene Spalte dafür.
 *
 * Ist ein Service nicht erreichbar (oder antwortet unbrauchbar) → [CryptoUnavailable], damit der Client sagen kann,
 * welcher Dienst fehlt. Einträge des anderen Service gehen weiter.
 */
class CryptoServices(private val clients: Map<CryptoAlg, CryptoServiceClient>) {

    constructor(aes: CryptoServiceClient, chacha: CryptoServiceClient) :
        this(mapOf(CryptoAlg.AES to aes, CryptoAlg.CHACHA to chacha))

    suspend fun encrypt(alg: CryptoAlg, userId: String, part: CryptoPart, c1: ByteArray, itemId: String? = null): ByteArray =
        withClient(alg) { it.encrypt(userId, part, c1, itemId) }

    suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String? = null): ByteArray =
        withClient(algOf(c2)) { it.decrypt(userId, part, c2, itemId) }

    /**
     * Wer das gespeicherte [c2] gemacht hat. Unbekanntes Format kommt nicht vom Crypto-Service,
     * sondern wurde in der DB verändert → [IntegrityError]. Nie raten.
     */
    fun algOf(c2: ByteArray): CryptoAlg = CryptoAlg.ofC2(c2) ?: throw IntegrityError()

    private suspend fun <T> withClient(alg: CryptoAlg, block: suspend (CryptoServiceClient) -> T): T {
        val client = clients[alg] ?: throw CryptoUnavailable(alg.wire, UpstreamException("no client for ${alg.wire}"))
        return try {
            block(client)
        } catch (e: UpstreamException) {
            throw CryptoUnavailable(alg.wire, e)
        }
    }
}
