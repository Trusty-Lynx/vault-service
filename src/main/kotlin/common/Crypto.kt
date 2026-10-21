package de.trustylynx.common

import java.security.MessageDigest
import java.security.SecureRandom

// Wie im auth-service (common/Crypto.kt). SecureRandom ist thread-safe.
private val secureRandom = SecureRandom()

/** Kryptografisch sichere Zufallsbytes für Salts und Tokens. */
fun secureRandomBytes(size: Int): ByteArray = ByteArray(size).also(secureRandom::nextBytes)

fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
