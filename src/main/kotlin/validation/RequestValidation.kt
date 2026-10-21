package de.trustylynx.validation

import de.trustylynx.api.CreateVaultRequest
import de.trustylynx.api.PutItemRequest
import de.trustylynx.api.UnlockVaultRequest
import de.trustylynx.common.BadRequest
import de.trustylynx.common.Caller
import de.trustylynx.domain.NewItem
import de.trustylynx.domain.NewVault

// Ganze Requests prüfen und in Domain-Objekte übersetzen. Wirft [BadRequest].
// Ein Request läuft immer api → validation → domain, die Domain bekommt nur geprüfte Daten.

/** POST /vault */
fun CreateVaultRequest.validate(caller: Caller): NewVault = NewVault(
    caller = caller,
    saltVault = validateBase64(salt, SALT_VAULT_LENGTH),
    kdf = validateKdf(kdf),
    unlockKey = validateUnlockKey(unlockKey),
    wdek = validateWdek(wdek),
)

/** POST /vault/unlock → der unlockKey (32 Byte). */
fun UnlockVaultRequest.validate(): ByteArray = validateUnlockKey(unlockKey)

/** PUT /items. Die [itemId] kommt aus dem Header X-Item-Id. */
fun PutItemRequest.validate(itemId: String): NewItem = NewItem(
    itemId = itemId,
    rev = validateRev(rev),
    head = validateC1(head, "head"),
    secret = validateC1(secret, "secret"),
)
