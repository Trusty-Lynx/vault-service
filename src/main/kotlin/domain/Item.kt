package de.trustylynx.domain

/** Bereits geprüfte Daten für PUT /items: Kopf und Geheimnis als C1 (Schicht 1, vom Client verschlüsselt). */
class NewItem(
    val itemId: String,
    val rev: Int,
    val head: ByteArray,
    val secret: ByteArray,
) {
    override fun toString(): String = "NewItem(itemId=$itemId, rev=$rev)"
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
