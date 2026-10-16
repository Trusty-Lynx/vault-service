package de.trustylynx.domain

import de.trustylynx.common.Caller

/**
 * Bereits validierte Daten für POST /vault.
 * Keine Sicherheitsstufe: US-28 ist Won't, alles läuft über Crypto 1 (AES-256-GCM).
 */
class NewVault(
    val caller: Caller,
    val saltVault: ByteArray,
    val kdf: KdfParams,
    val unlockKey: ByteArray,
    val wdek: ByteArray,
) {
    override fun toString(): String = "NewVault(userId=${caller.userId})"
}
