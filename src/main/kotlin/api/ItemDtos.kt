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
