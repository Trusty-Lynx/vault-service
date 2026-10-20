package de.trustylynx.common

import java.security.SecureRandom

/** Kryptografisch sichere Zufallsbytes für Salts und Tokens. SecureRandom ist thread-safe. */
object SecureRandomBytes {
    private val random = SecureRandom()

    fun next(length: Int): ByteArray = ByteArray(length).also(random::nextBytes)
}
