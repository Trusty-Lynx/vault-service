package de.trustylynx.domain

import de.trustylynx.clients.CryptoAlg

/**
 * Bereits geprüfte Daten für PUT /items: Kopf und Geheimnis als C1 (Schicht 1, vom Client verschlüsselt).
 * [alg]: welcher Crypto-Service Schicht 2 um beide Teile legt (vom Nutzer gewählt).
 */
class NewItem(
    val itemId: String,
    val rev: Int,
    val head: ByteArray,
    val secret: ByteArray,
    val alg: CryptoAlg,
) {
    override fun toString(): String = "NewItem(itemId=$itemId, rev=$rev, alg=${alg.wire})"
}

/** Ein Eintrag, so wie er in `items` steht: beide Teile mit Schicht 2 (C2). */
class StoredItem(
    val itemId: String,
    val rev: Int,
    val headC2: ByteArray,
    val secretC2: ByteArray,
) {
    override fun toString(): String = "StoredItem(itemId=$itemId, rev=$rev)"
}

/** Kopf eines Eintrags aus `items`, noch mit Schicht 2 (für GET /items). */
class StoredHead(
    val itemId: String,
    val rev: Int,
    val headC2: ByteArray,
) {
    override fun toString(): String = "StoredHead(itemId=$itemId, rev=$rev)"
}

/** Kopf eines Eintrags ohne Schicht 2, also C1. Öffnen kann ihn nur der Client mit dem DEK. [alg] aus dem C2-Header. */
class ItemHead(
    val itemId: String,
    val rev: Int,
    val head: ByteArray,
    val alg: CryptoAlg,
) {
    override fun toString(): String = "ItemHead(itemId=$itemId, rev=$rev, alg=${alg.wire})"
}

/** Geheimnis eines Eintrags aus `items`, noch mit Schicht 2 (für GET /items/secret). */
class StoredSecret(
    val rev: Int,
    val secretC2: ByteArray,
) {
    override fun toString(): String = "StoredSecret(rev=$rev)"
}

/** Geheimnis ohne Schicht 2, also C1. Öffnen kann es nur der Client mit dem DEK. */
class ItemSecret(
    val rev: Int,
    val secret: ByteArray,
) {
    override fun toString(): String = "ItemSecret(rev=$rev)"
}
