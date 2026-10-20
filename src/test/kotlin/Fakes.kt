package de.trustylynx

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.common.AlreadyExists
import de.trustylynx.common.Caller
import de.trustylynx.common.IntegrityError
import de.trustylynx.common.UpstreamException
import de.trustylynx.domain.StoredHead
import de.trustylynx.domain.StoredItem
import de.trustylynx.domain.StoredSecret
import de.trustylynx.domain.Vault
import de.trustylynx.domain.VaultSession
import de.trustylynx.persistence.ItemRepository
import de.trustylynx.persistence.VaultRepository
import java.time.Instant

// Gemeinsame Fakes für VaultRoutesTest und ItemRoutesTest. Verhalten wie die Postgres-Repositories, nur im Speicher.

internal class FakeVaultRepository : VaultRepository {
    var failWithConflict = false
    var vault: Vault? = null
    val sessions = mutableListOf<VaultSession>()

    override suspend fun exists(userId: String) = vault?.userId == userId

    override suspend fun find(userId: String) = vault?.takeIf { it.userId == userId }

    override suspend fun create(vault: Vault, session: VaultSession) {
        if (failWithConflict) throw AlreadyExists()
        this.vault = vault
        sessions += session
    }

    override suspend fun createSession(session: VaultSession) {
        sessions += session
    }

    // Gleiche Bedingung wie im SQL von PostgresVaultRepository.
    private fun VaultSession.matches(tokenHash: ByteArray, caller: Caller, now: Instant) =
        this.tokenHash.contentEquals(tokenHash) && userId == caller.userId && deviceId == caller.deviceId &&
            sessionId == caller.sessionId && expiresAt.isAfter(now)

    override suspend fun touchSession(tokenHash: ByteArray, caller: Caller, now: Instant, newExpiresAt: Instant): Boolean {
        val index = sessions.indexOfFirst { it.matches(tokenHash, caller, now) }
        if (index < 0) return false
        val old = sessions[index]
        sessions[index] = VaultSession(old.tokenHash, old.userId, old.deviceId, old.sessionId, newExpiresAt)
        return true
    }

    override suspend fun deleteSession(tokenHash: ByteArray, caller: Caller, now: Instant): Boolean =
        sessions.removeIf { it.matches(tokenHash, caller, now) }

    override suspend fun deleteExpiredSessions(userId: String, now: Instant) {
        sessions.removeIf { it.userId == userId && !it.expiresAt.isAfter(now) }
    }
}

internal class FakeItemRepository : ItemRepository {
    /** Schlüssel: userId to itemId. */
    val items = mutableMapOf<Pair<String, String>, StoredItem>()

    /** Simuliert einen parallelen Request, der zwischen Vorab-Prüfung und Speichern gewinnt. */
    var loseRaceWithRev: Int? = null

    override suspend fun currentRev(userId: String, itemId: String): Int? = items[userId to itemId]?.rev

    override suspend fun insert(userId: String, item: StoredItem): Boolean {
        loseRaceWithRev?.let { items[userId to item.itemId] = item.copyWithRev(it); return false }
        if ((userId to item.itemId) in items) return false
        items[userId to item.itemId] = item
        return true
    }

    override suspend fun update(userId: String, item: StoredItem, previousRev: Int): Boolean {
        loseRaceWithRev?.let { items[userId to item.itemId] = item.copyWithRev(it); return false }
        if (items[userId to item.itemId]?.rev != previousRev) return false
        items[userId to item.itemId] = item
        return true
    }

    override suspend fun listHeads(userId: String): List<StoredHead> =
        items.filterKeys { it.first == userId }.values.sortedBy { it.itemId }.map { StoredHead(it.itemId, it.rev, it.headC2) }

    override suspend fun findSecret(userId: String, itemId: String): StoredSecret? =
        items[userId to itemId]?.let { StoredSecret(it.rev, it.secretC2) }

    override suspend fun delete(userId: String, itemId: String): Boolean = items.remove(userId to itemId) != null

    private fun StoredItem.copyWithRev(rev: Int) = StoredItem(itemId, rev, headC2, secretC2)
}

internal class FakeKeyService : KeyServiceClient {
    var fail = false
    var calledWith: Pair<String, ByteArray>? = null

    override suspend fun pepperHmac(userId: String, unlockKey: ByteArray): ByteArray {
        calledWith = userId to unlockKey.copyOf()
        if (fail) throw UpstreamException("key-service down")
        return h(unlockKey)
    }

    companion object {
        // Kein echtes HMAC, aber wie HMAC: anderer unlockKey → anderes h.
        fun h(unlockKey: ByteArray): ByteArray = ByteArray(32) { (unlockKey[it] + 1).toByte() }
    }
}

internal class FakeCryptoService : CryptoServiceClient {
    var fail = false
    var integrityError = false

    /** Alle Aufrufe in Reihenfolge: userId, part, itemId. */
    val calls = mutableListOf<Triple<String, CryptoPart, String?>>()

    /** Der letzte Aufruf (reicht für Tresor-Endpunkte, die nur einmal aufrufen). */
    val calledWith: Triple<String, CryptoPart, String?>? get() = calls.lastOrNull()

    override suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String?): ByteArray {
        calls += Triple(userId, part, itemId)
        if (fail) throw UpstreamException("crypto-service down")
        return c2Of(c1)
    }

    override suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String?): ByteArray {
        calls += Triple(userId, part, itemId)
        if (fail) throw UpstreamException("crypto-service down")
        if (integrityError) throw IntegrityError()
        return c2.copyOfRange(HEADER.size, c2.size - FILLER)
    }

    companion object {
        private val HEADER = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, 0x02, 0x00, 0x01)
        private const val FILLER = 28

        // Kein echtes ChaCha20, nur erkennbar: TLX2-Header + c1 + 28 Byte Füllung = c1 + 36 Byte
        fun c2Of(c1: ByteArray): ByteArray = HEADER + c1 + ByteArray(FILLER)
    }
}
