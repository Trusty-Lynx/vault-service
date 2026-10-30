package de.trustylynx.api

import de.trustylynx.domain.KdfParams
import kotlinx.serialization.Serializable

/**
 * POST /internal/vault/unlocked (vom Breach-Service). userId und sessionId hat der Aufrufer vorher beim Auth-Service geprüft,
 * deviceId ist dieselbe wie beim Entsperren (oder NO_DEVICE_ID).
 */
@Serializable
data class VerifyUnlockedRequest(
    val userId: String,
    val sessionId: String,
    val deviceId: String,
    val vaultToken: String,
) {
    // Ohne Tresor-Token, damit er nie im Log landet.
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

/** `alg`: welcher Crypto-Service Schicht 2 macht, `aes` oder `chacha`. Fehlt es → `chacha` (bisheriges Verhalten). */
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

/**
 * Ein Kopf in GET /items. `head` ist C1, der Client öffnet ihn mit aad1 = TL-L1|{userId}|{id}|h|{rev}.
 * `alg` (`aes` / `chacha`): mit welchem Crypto-Service der Eintrag gespeichert ist.
 */
@Serializable
data class ItemHeadResponse(
    val id: String,
    val rev: Int,
    val head: String,
    val alg: String,
)

/** GET /items/secret. `data` ist C1, der Client öffnet es mit aad1 = TL-L1|{userId}|{itemId}|s|{rev}. */
@Serializable
data class ItemSecretResponse(
    val data: String,
    val rev: Int,
)
