package de.trustylynx.models

import kotlinx.serialization.Serializable
import java.time.Instant

@Serializable
data class KdfParams(
    val alg: String,
    val m: Int,
    val t: Int,
    val p: Int,
    val len: Int,
) {
    companion object {
        val DEFAULT = KdfParams(alg = "argon2id", m = 65536, t = 3, p = 1, len = 32)
    }
}

class Vault(
    val userId: String,
    val saltVault: ByteArray,
    val kdf: KdfParams,
    val saltSVault: ByteArray,
    val vaultVerifier: ByteArray,
    val wdekC2: ByteArray,
)

// an unlocked vault for one login session. Only the hash of the token is stored
class VaultSession(
    val tokenHash: ByteArray,
    val userId: String,
    val sessionId: String,
    val expiresAt: Instant,
)
