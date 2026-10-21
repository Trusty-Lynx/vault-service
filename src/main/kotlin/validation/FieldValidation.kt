package de.trustylynx.validation

import de.trustylynx.common.BadRequest
import de.trustylynx.common.decodeBase64OrNull
import de.trustylynx.domain.KdfParams

// Einzelne Felder prüfen. Ganze Requests setzt RequestValidation.kt daraus zusammen.
// Den Inhalt der verschlüsselten Felder kann der Server nie prüfen (die Schlüssel kennt nur der Client), nur das Format.

internal const val SALT_VAULT_LENGTH = 16
internal const val UNLOCK_KEY_LENGTH = 32

// wDEK = Version (01) ‖ Algorithmus (01) ‖ nonce_w (12) ‖ AES-256-GCM(DEK, 32 + 16 Tag) = 62 Byte
private const val WDEK_LENGTH = 62

// C1 = Version (01) ‖ Algorithmus (01) ‖ nonce (12) ‖ AES-256-GCM(Padding-Block) ‖ Tag (16) → Padding-Block + 30 Byte.
// Gleiche Regeln wie Tlx2.isValidC1 im ChaCha-Service, damit er nichts ablehnt, was wir angenommen haben.
private const val C1_OVERHEAD = 30
private const val MIN_PADDING_BLOCK = 32
private const val MAX_PADDING_BLOCK = 65_536

// Schicht 1 (wDEK und C1) beginnt immer mit Version 01 und Algorithmus 01 (AES-256-GCM).
private const val LAYER1_VERSION: Byte = 0x01
private const val LAYER1_ALG_AES_GCM: Byte = 0x01

/** Dekodiert Base64 mit genau [length] Bytes oder wirft [BadRequest]. */
internal fun validateBase64(value: String, length: Int): ByteArray {
    if (value.length != (length + 2) / 3 * 4) throw BadRequest("invalid base64 length, expected $length bytes")
    val bytes = value.decodeBase64OrNull() ?: throw BadRequest("invalid base64 encoding")
    if (bytes.size != length) throw BadRequest("decoded value must be $length bytes")
    return bytes
}

internal fun validateUnlockKey(value: String): ByteArray = validateBase64(value, UNLOCK_KEY_LENGTH)

internal fun validateKdf(kdf: KdfParams): KdfParams {
    if (kdf != KdfParams.DEFAULT) throw BadRequest("unsupported kdf parameters")
    return kdf
}

internal fun validateWdek(value: String): ByteArray {
    val bytes = validateBase64(value, WDEK_LENGTH)
    if (!bytes.startsWithLayer1Header()) throw BadRequest("wdek must start with 01 01")
    return bytes
}

/** Kopf oder Geheimnis eines Eintrags als C1. [field] steht in der Fehlermeldung. */
internal fun validateC1(value: String, field: String): ByteArray {
    val bytes = value.decodeBase64OrNull() ?: throw BadRequest("$field: invalid base64")
    if (!bytes.startsWithLayer1Header()) throw BadRequest("$field must start with 01 01")
    val block = bytes.size - C1_OVERHEAD
    // Padding-Block ist immer eine Zweierpotenz (V5), z. B. 32, 64, 128 … Byte.
    if (block !in MIN_PADDING_BLOCK..MAX_PADDING_BLOCK || block and (block - 1) != 0) {
        throw BadRequest("$field: padding block must be a power of two between $MIN_PADDING_BLOCK and $MAX_PADDING_BLOCK bytes")
    }
    return bytes
}

internal fun validateRev(rev: Int): Int {
    if (rev < 1) throw BadRequest("rev must be at least 1")
    return rev
}

private fun ByteArray.startsWithLayer1Header() =
    size >= 2 && this[0] == LAYER1_VERSION && this[1] == LAYER1_ALG_AES_GCM
