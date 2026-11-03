package de.trustylynx.models

import kotlinx.serialization.Serializable

@Serializable
data class VerifyUnlockedRequest(
    val userId: String,
    val sessionId: String,
    val deviceId: String,
    val vaultToken: String,
) {
    // leaves out the vault token so it never ends up in a log
    override fun toString() = "VerifyUnlockedRequest(userId=$userId, sessionId=$sessionId, deviceId=$deviceId)"
}

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
data class VaultParamsResponse(
    val salt: String,
    val kdf: KdfParams,
)

@Serializable
data class UnlockVaultRequest(
    val unlockKey: String,
)

@Serializable
data class UnlockVaultResponse(
    val vaultToken: String,
    // seconds without a vault request until the server locks the vault
    val expiresIn: Long,
    val wdek: String,
)

// no alg means chacha, so older clients can still save
@Serializable
data class PutItemRequest(
    val rev: Int,
    val head: String,
    val secret: String,
    val alg: String? = null,
)

@Serializable
data class PutItemResponse(
    val rev: Int,
)

@Serializable
data class ListItemsResponse(
    val items: List<ItemHeadResponse>,
)

// head is C1, the client opens it with aad1 = TL-L1|{userId}|{id}|h|{rev}
@Serializable
data class ItemHeadResponse(
    val id: String,
    val rev: Int,
    val head: String,
    val alg: String,
)

// data is C1, the client opens it with aad1 = TL-L1|{userId}|{itemId}|s|{rev}
@Serializable
data class ItemSecretResponse(
    val data: String,
    val rev: Int,
)
