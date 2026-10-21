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
data class VaultParamsResponse(
    /** salt_vault, 16 Byte, Base64. */
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
    /** Sekunden ohne Tresor-Anfrage bis zur serverseitigen Sperre (900 = 15 min). */
    val expiresIn: Long,
    val wdek: String,
)

// ---------- Einträge ----------

// Die itemId steht nicht im Body, sondern im Header X-Item-Id (siehe ITEM_ID_HEADER).

@Serializable
data class PutItemRequest(
    val rev: Int,
    val head: String,
    val secret: String,
)

@Serializable
data class PutItemResponse(
    val rev: Int,
)

@Serializable
data class ListItemsResponse(
    val items: List<ItemHeadResponse>,
)

/** Ein Kopf in GET /items. `head` ist C1, der Client öffnet ihn mit aad1 = TL-L1|{userId}|{id}|h|{rev}. */
@Serializable
data class ItemHeadResponse(
    val id: String,
    val rev: Int,
    val head: String,
)

/** GET /items/secret. `data` ist C1, der Client öffnet es mit aad1 = TL-L1|{userId}|{itemId}|s|{rev}. */
@Serializable
data class ItemSecretResponse(
    val data: String,
    val rev: Int,
)
