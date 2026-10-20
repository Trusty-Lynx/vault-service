package de.trustylynx.security

import de.trustylynx.common.SecureRandomBytes
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64

/** Tresor-Token: 32 Zufallsbytes, Base64url. In der DB steht nur SHA-256 davon. */
object VaultToken {
    const val LENGTH = 32

    /** Leerlaufzeit: Nach 15 min ohne Tresor-Anfrage ist der Token abgelaufen. */
    val IDLE_TIMEOUT: Duration = Duration.ofMinutes(15)

    // 32 Byte als Base64url ohne Padding = genau 43 Zeichen.
    private val FORMAT = Regex("^[A-Za-z0-9_-]{43}$")

    fun generate(): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(SecureRandomBytes.next(LENGTH))

    /** Sieht aus wie ein von uns ausgestellter Token? Alles andere gar nicht erst in der DB suchen. */
    fun isWellFormed(token: String): Boolean = FORMAT.matches(token)

    // SHA-256 statt Argon2 reicht: 32 Zufallsbytes kann niemand erraten, da muss nichts gebremst werden.
    fun hash(token: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.US_ASCII))
}
