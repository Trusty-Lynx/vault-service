package de.trustylynx.security

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

// SecureRandom is thread-safe, one instance is enough
private val secureRandom = SecureRandom()

fun secureRandomBytes(size: Int): ByteArray = ByteArray(size).also(secureRandom::nextBytes)

fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)

fun String.decodeBase64OrNull(): ByteArray? = try {
    Base64.getDecoder().decode(this)
} catch (_: IllegalArgumentException) {
    null
}
