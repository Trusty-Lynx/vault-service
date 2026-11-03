package de.trustylynx.models

// rows from the items table, everything still wrapped in layer 2 (C2)

class StoredItem(
    val itemId: String,
    val rev: Int,
    val headC2: ByteArray,
    val secretC2: ByteArray,
)

class StoredHead(
    val itemId: String,
    val rev: Int,
    val headC2: ByteArray,
)

class StoredSecret(
    val rev: Int,
    val secretC2: ByteArray,
)
