package de.trustylynx.api

import de.trustylynx.common.BadRequest
import de.trustylynx.common.Caller
import de.trustylynx.common.validateBase64
import de.trustylynx.domain.KdfParams
import de.trustylynx.domain.NewVault

const val SALT_VAULT_LENGTH = 16
const val UNLOCK_KEY_LENGTH = 32

// wDEK = Version (01) ‖ Algorithmus (01) ‖ nonce_w (12) ‖ AES-256-GCM(DEK, 32 + 16 Tag) = 62 Byte
const val WDEK_LENGTH = 62
private const val WDEK_VERSION: Byte = 0x01
private const val WDEK_ALG_AES_GCM: Byte = 0x01

/** Prüft den Request und liefert nur geprüfte Daten an die Domain. Wirft [BadRequest]. */
fun CreateVaultRequest.validate(caller: Caller): NewVault = NewVault(
    caller = caller,
    saltVault = validateBase64(salt, SALT_VAULT_LENGTH),
    kdf = validateKdf(kdf),
    unlockKey = validateBase64(unlockKey, UNLOCK_KEY_LENGTH),
    wdek = validateWdek(wdek),
)

private fun validateKdf(kdf: KdfParams): KdfParams {
    if (kdf != KdfParams.DEFAULT) throw BadRequest("unsupported kdf parameters")
    return kdf
}

// Den Inhalt kann der Server nicht prüfen (KEK kennt nur der Client), nur das Format.
private fun validateWdek(value: String): ByteArray {
    val bytes = validateBase64(value, WDEK_LENGTH)
    if (bytes[0] != WDEK_VERSION || bytes[1] != WDEK_ALG_AES_GCM) throw BadRequest("wdek must start with 01 01")
    return bytes
}
