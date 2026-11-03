package de.trustylynx.clients

import de.trustylynx.models.CryptoUnavailable
import de.trustylynx.models.IntegrityError
import de.trustylynx.models.UpstreamException

// The user picks a crypto service per item. Encrypt goes to the picked one, decrypt goes to the one named in the
// algorithm byte of the stored C2, that's why the DB doesn't need a column for it.
// If one service is down, only its items fail with CryptoUnavailable, the others keep working.
class CryptoServices(
    private val aes: CryptoServiceClient,
    private val chacha: CryptoServiceClient,
) {
    suspend fun encrypt(alg: CryptoAlg, userId: String, part: CryptoPart, c1: ByteArray, itemId: String? = null): ByteArray =
        withClient(alg) { it.encrypt(userId, part, c1, itemId) }

    suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String? = null): ByteArray =
        withClient(algOf(c2)) { it.decrypt(userId, part, c2, itemId) }

    // An unknown format can't come from a crypto service, so someone changed the DB. Never guess
    fun algOf(c2: ByteArray): CryptoAlg = CryptoAlg.ofC2(c2) ?: throw IntegrityError()

    private suspend fun <T> withClient(alg: CryptoAlg, block: suspend (CryptoServiceClient) -> T): T {
        val client = when (alg) {
            CryptoAlg.AES -> aes
            CryptoAlg.CHACHA -> chacha
        }
        return try {
            block(client)
        } catch (e: UpstreamException) {
            throw CryptoUnavailable(alg.wire, e)
        }
    }
}
