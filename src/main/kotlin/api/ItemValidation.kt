package de.trustylynx.api

import de.trustylynx.common.BadRequest
import de.trustylynx.common.decodeBase64OrNull
import de.trustylynx.domain.NewItem

// C1 = Version (01) ‖ Algorithmus (01) ‖ nonce (12) ‖ AES-256-GCM(Padding-Block) ‖ Tag (16) → Padding-Block + 30 Byte.
// Gleiche Regeln wie Tlx2.isValidC1 im ChaCha-Service, damit er nichts ablehnt, was wir angenommen haben.
private const val C1_OVERHEAD = 30
private const val MIN_PADDING_BLOCK = 32
private const val MAX_PADDING_BLOCK = 65_536

/** Prüft den Request und liefert nur geprüfte Daten an die Domain. Wirft [BadRequest]. */
fun PutItemRequest.validate(itemId: String): NewItem {
    if (rev < 1) throw BadRequest("rev must be at least 1")
    return NewItem(
        itemId = itemId,
        rev = rev,
        head = validateC1(head, "head"),
        secret = validateC1(secret, "secret"),
    )
}

// Den Inhalt kann der Server nicht prüfen (DEK kennt nur der Client), nur das Format.
private fun validateC1(value: String, field: String): ByteArray {
    val bytes = value.decodeBase64OrNull() ?: throw BadRequest("$field: invalid base64")
    if (bytes.size < 2 || bytes[0] != 0x01.toByte() || bytes[1] != 0x01.toByte()) throw BadRequest("$field must start with 01 01")
    val block = bytes.size - C1_OVERHEAD
    // Padding-Block ist immer eine Zweierpotenz (V5), z. B. 32, 64, 128 … Byte.
    if (block !in MIN_PADDING_BLOCK..MAX_PADDING_BLOCK || block and (block - 1) != 0) {
        throw BadRequest("$field: padding block must be a power of two between $MIN_PADDING_BLOCK and $MAX_PADDING_BLOCK bytes")
    }
    return bytes
}
