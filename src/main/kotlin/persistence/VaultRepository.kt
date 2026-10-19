package de.trustylynx.persistence

import de.trustylynx.domain.Vault
import de.trustylynx.domain.VaultSession

interface VaultRepository {
    suspend fun exists(userId: String): Boolean

    /** Speichert Tresor und ersten Tresor-Token zusammen. Gibt es den Tresor schon → [de.trustylynx.common.AlreadyExists]. */
    suspend fun create(vault: Vault, session: VaultSession)
}
