package de.trustylynx.api

import kotlinx.serialization.Serializable

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
