package de.trustylynx.api

import de.trustylynx.domain.KdfParams
import kotlinx.serialization.Serializable

@Serializable
data class CreateVaultRequest(
    val salt: String,
    val kdf: KdfParams,
    val unlockKey: String,
    val wdek: String,
)

@Serializable
data class CreateVaultResponse(
    val vaultToken: String,
)

@Serializable
data class UnlockVaultRequest(
    val unlockKey: String,
)

@Serializable
data class UnlockVaultResponse(
    val vaultToken: String,
    /** Sekunden ohne Tresor-Anfrage bis zur serverseitigen Sperre (900 = 15 min). */
    val expiresIn: Long,
    val wdek: String,
)
