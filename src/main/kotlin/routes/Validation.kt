package de.trustylynx.routes

import de.trustylynx.clients.CryptoAlg
import de.trustylynx.models.BadRequest
import de.trustylynx.models.Caller
import de.trustylynx.models.ITEM_ID_HEADER
import de.trustylynx.models.KdfParams
import de.trustylynx.models.isValidId
import de.trustylynx.security.decodeBase64OrNull
import io.ktor.server.application.ApplicationCall

// We can only check the format of the encrypted fields, never the content, only the client has the keys.

internal const val SALT_VAULT_LENGTH = 16
private const val UNLOCK_KEY_LENGTH = 32

// wDEK = version (01) | algorithm (01) | nonce_w (12) | AES-256-GCM(DEK, 32 + 16 tag) = 62 bytes
private const val WDEK_LENGTH = 62

// C1 = version (01) | algorithm (01) | nonce (12) | AES-256-GCM(padding block) | tag (16) = padding block + 30 bytes.
// Same rules as Tlx2.isValidC1 in the ChaCha service, so it never rejects something we accepted
private const val C1_OVERHEAD = 30
private const val MIN_PADDING_BLOCK = 32
private const val MAX_PADDING_BLOCK = 65_536

// layer 1 (wDEK and C1) always starts with version 01 and algorithm 01 (AES-256-GCM)
private const val LAYER1_VERSION: Byte = 0x01
private const val LAYER1_ALG_AES_GCM: Byte = 0x01

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

// field only goes into the error message
internal fun validateC1(value: String, field: String): ByteArray {
    val bytes = value.decodeBase64OrNull() ?: throw BadRequest("$field: invalid base64")
    if (!bytes.startsWithLayer1Header()) throw BadRequest("$field must start with 01 01")
    val block = bytes.size - C1_OVERHEAD
    // the padding block is always a power of two (32, 64, 128, ... bytes)
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

// no alg means chacha, so older clients can still save
internal fun validateAlg(alg: String?): CryptoAlg {
    if (alg == null) return CryptoAlg.CHACHA
    return CryptoAlg.fromWire(alg) ?: throw BadRequest("unknown alg")
}

// only the ids, a broken vault token is just "locked" (vault_locked) in VaultService and not a 400
internal fun validateCaller(userId: String, sessionId: String): Caller {
    if (!isValidId(userId) || !isValidId(sessionId)) throw BadRequest("invalid ids")
    return Caller(userId = userId, sessionId = sessionId)
}

fun ApplicationCall.itemId(): String {
    val value = request.headers[ITEM_ID_HEADER] ?: throw BadRequest("missing $ITEM_ID_HEADER")
    if (!isValidId(value)) throw BadRequest("invalid $ITEM_ID_HEADER")
    return value
}
