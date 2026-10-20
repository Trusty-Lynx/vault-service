package de.trustylynx.persistence

import de.trustylynx.common.Caller
import de.trustylynx.domain.Vault
import de.trustylynx.domain.VaultSession
import java.time.Instant

interface VaultRepository {
    suspend fun exists(userId: String): Boolean

    /** Der Tresor des Nutzers, oder null, wenn es (noch) keinen gibt. */
    suspend fun find(userId: String): Vault?

    /** Speichert Tresor und ersten Tresor-Token zusammen. Gibt es den Tresor schon → [de.trustylynx.common.AlreadyExists]. */
    suspend fun create(vault: Vault, session: VaultSession)

    /** Speichert einen weiteren Tresor-Token (nach dem Entsperren). */
    suspend fun createSession(session: VaultSession)

    /**
     * Prüft und verlängert einen Tresor-Token in einem Schritt (atomar):
     * Passt [tokenHash] zu userId, deviceId und sessionId von [caller] und ist er nach [now] noch gültig,
     * wird `expires_at` auf [newExpiresAt] gesetzt → true. Sonst bleibt alles, wie es ist → false.
     */
    suspend fun touchSession(tokenHash: ByteArray, caller: Caller, now: Instant, newExpiresAt: Instant): Boolean

    /** Löscht einen Tresor-Token, wenn er zu [caller] gehört und nach [now] noch gültig ist → true. Sonst false. */
    suspend fun deleteSession(tokenHash: ByteArray, caller: Caller, now: Instant): Boolean

    /** Räumt abgelaufene Tresor-Tokens des Nutzers weg, damit `vault_sessions` nicht endlos wächst. */
    suspend fun deleteExpiredSessions(userId: String, now: Instant)
}
