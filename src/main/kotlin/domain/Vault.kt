package de.trustylynx.domain

import de.trustylynx.common.Caller
import kotlinx.serialization.Serializable
import java.time.Duration
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

/**
 * Bereits validierte Daten für POST /vault.
 * Keine Sicherheitsstufe: US-28 ist Won't. Schicht 2 läuft immer über Crypto-Service 2 (ChaCha20-Poly1305),
 * weil nur dieser Service existiert (Entscheid 2026-10-20).
 */
class NewVault(
    val caller: Caller,
    val saltVault: ByteArray,
    val kdf: KdfParams,
    val unlockKey: ByteArray,
    val wdek: ByteArray,
) {
    override fun toString(): String = "NewVault(userId=${caller.userId})"
}

/** Ein Tresor, so wie er in `vaults` steht. */
class Vault(
    val userId: String,
    val saltVault: ByteArray,
    val kdf: KdfParams,
    val saltSVault: ByteArray,
    val vaultVerifier: ByteArray,
    val wdekC2: ByteArray,
) {
    override fun toString(): String = "Vault(userId=$userId)"
}

/** Ein entsperrter Tresor auf einem Gerät, so wie er in `vault_sessions` steht. Nur der Hash des Tokens. */
class VaultSession(
    val tokenHash: ByteArray,
    val userId: String,
    val deviceId: String,
    val sessionId: String,
    val expiresAt: Instant,
) {
    override fun toString(): String = "VaultSession(userId=$userId, deviceId=$deviceId, expiresAt=$expiresAt)"
}

/** Ergebnis von GET /vault/params. */
class VaultParams(
    val saltVault: ByteArray,
    val kdf: KdfParams,
)

/** Ergebnis von POST /vault/unlock. */
class UnlockedVault(
    val vaultToken: String,
    val expiresIn: Duration,
    val wdek: ByteArray,
) {
    override fun toString(): String = "UnlockedVault(expiresIn=$expiresIn)"
}
