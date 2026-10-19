package de.trustylynx.security

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.MessageDigest

object VerifierHasher {
    const val MEMORY_KIB = 19456
    const val ITERATIONS = 2
    const val PARALLELISM = 1
    const val LENGTH = 32
    const val SALT_LENGTH = 16

    fun hash(h: ByteArray, saltSVault: ByteArray): ByteArray {
        require(saltSVault.size == SALT_LENGTH) { "salt_s_vault must be $SALT_LENGTH bytes" }
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(MEMORY_KIB)
            .withIterations(ITERATIONS)
            .withParallelism(PARALLELISM)
            .withSalt(saltSVault)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(parameters)
        val verifier = ByteArray(LENGTH)
        generator.generateBytes(h, verifier)
        return verifier
    }

    fun matches(h: ByteArray, saltSVault: ByteArray, vaultVerifier: ByteArray): Boolean =
        MessageDigest.isEqual(hash(h, saltSVault), vaultVerifier)
}
