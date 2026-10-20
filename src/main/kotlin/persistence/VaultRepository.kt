package de.trustylynx.persistence

import de.trustylynx.domain.Vault
import de.trustylynx.domain.VaultSession

interface VaultRepository {
    suspend fun exists(userId: String): Boolean

    /** Der Tresor des Nutzers, oder null, wenn es (noch) keinen gibt. */
    suspend fun find(userId: String): Vault?

    /** Speichert Tresor und ersten Tresor-Token zusammen. Gibt es den Tresor schon → [de.trustylynx.common.AlreadyExists]. */
    suspend fun create(vault: Vault, session: VaultSession)

    /** Speichert einen weiteren Tresor-Token (nach dem Entsperren). */
    suspend fun createSession(session: VaultSession)
}
