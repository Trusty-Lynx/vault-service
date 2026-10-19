package de.trustylynx.domain

import java.time.Instant

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
