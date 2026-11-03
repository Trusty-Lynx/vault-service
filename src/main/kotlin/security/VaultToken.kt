package de.trustylynx.security

import java.time.Duration
import java.util.Base64

// 32 random bytes as Base64url, the DB only stores the SHA-256 of it
object VaultToken {
    const val LENGTH = 32

    // the token expires after 15 minutes without a vault request
    val IDLE_TIMEOUT: Duration = Duration.ofMinutes(15)

    // 32 bytes as Base64url without padding = exactly 43 characters
    private val FORMAT = Regex("^[A-Za-z0-9_-]{43}$")

    fun generate(): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(secureRandomBytes(LENGTH))

    // anything that doesn't look like one of our tokens isn't even looked up in the DB
    fun isWellFormed(token: String): Boolean = FORMAT.matches(token)

    // SHA-256 instead of Argon2 is enough: nobody can guess 32 random bytes, so there's nothing to slow down
    fun hash(token: String): ByteArray =
        sha256(token.toByteArray(Charsets.US_ASCII))
}
