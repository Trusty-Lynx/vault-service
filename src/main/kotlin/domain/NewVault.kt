package de.trustylynx.domain

import de.trustylynx.common.Caller

/**
 * Bereits validierte Daten für POST /vault.
 * Keine Sicherheitsstufe: US-28 ist Won't. Schicht 2 läuft immer über Crypto-Service 2 (ChaCha20-Poly1305),
 * weil nur dieser Service existiert (Entscheid 2026-10-20).
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
