package de.trustylynx.clients

/** Welcher Teil verschlüsselt wird. Geht beim Crypto-Service in die AAD ein. */
enum class CryptoPart(val wire: String) {
    HEAD("h"),
    SECRET("s"),
    DEK("dek"),
}

/** Zugriff auf Crypto-Service 1 (Schicht 2, AES-256-GCM). Als Interface, damit Tests einen Fake einsetzen können. */
interface CryptoServiceClient {
    /**
     * Legt Schicht 2 um [c1] und liefert C2 ("TLX2", 36 Byte länger als [c1]).
     * [itemId] ist Pflicht bei [CryptoPart.HEAD] und [CryptoPart.SECRET] und fehlt bei [CryptoPart.DEK].
     */
    suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String? = null): ByteArray
}
