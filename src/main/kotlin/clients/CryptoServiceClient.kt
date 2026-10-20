package de.trustylynx.clients

/** Welcher Teil verschlüsselt wird. Geht beim Crypto-Service in die AAD ein. */
enum class CryptoPart(val wire: String) {
    HEAD("h"),
    SECRET("s"),
    DEK("dek"),
}

/** Zugriff auf Crypto-Service 2 (Schicht 2, ChaCha20-Poly1305). Als Interface, damit Tests einen Fake einsetzen können. */
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
