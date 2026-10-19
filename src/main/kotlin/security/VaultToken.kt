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

    fun generate(): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(SecureRandomBytes.next(LENGTH))

    // SHA-256 statt Argon2 reicht: 32 Zufallsbytes kann niemand erraten, da muss nichts gebremst werden.
    fun hash(token: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.US_ASCII))
}
