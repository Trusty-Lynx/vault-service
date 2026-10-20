package de.trustylynx.clients

/** Zugriff auf den Key-Service. Als Interface, damit Tests einen Fake einsetzen können. */
interface KeyServiceClient {
    /**
     * V3 Schritt ①: h = HMAC-SHA256(pepper_vault, unlockKey), 32 Byte.
     * pepper_vault verlässt den Key-Service nie, der Vault-Service bekommt nur h.
     */
    suspend fun pepperHmac(userId: String, unlockKey: ByteArray): ByteArray
}
