package de.trustylynx

import de.trustylynx.clients.AuthServiceClient
import de.trustylynx.clients.CryptoAlg
import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.clients.VerifiedSession
import de.trustylynx.models.AlreadyExists
import de.trustylynx.models.Caller
import de.trustylynx.models.IntegrityError
import de.trustylynx.models.StoredHead
import de.trustylynx.models.StoredItem
import de.trustylynx.models.StoredSecret
import de.trustylynx.models.UpstreamException
import de.trustylynx.models.Vault
import de.trustylynx.models.VaultSession
import de.trustylynx.repositories.ItemRepository
import de.trustylynx.repositories.VaultRepository
import java.time.Instant
import java.util.Collections

// in-memory fakes that behave like the Postgres repositories

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

    // same condition as the SQL in PostgresVaultRepository
    private fun VaultSession.matches(tokenHash: ByteArray, caller: Caller, now: Instant) =
        this.tokenHash.contentEquals(tokenHash) && userId == caller.userId &&
            sessionId == caller.sessionId && expiresAt.isAfter(now)

    override suspend fun touchSession(tokenHash: ByteArray, caller: Caller, now: Instant, newExpiresAt: Instant): Boolean {
        val index = sessions.indexOfFirst { it.matches(tokenHash, caller, now) }
        if (index < 0) return false
        val old = sessions[index]
        sessions[index] = VaultSession(old.tokenHash, old.userId, old.sessionId, newExpiresAt)
        return true
    }

    override suspend fun deleteSession(tokenHash: ByteArray, caller: Caller, now: Instant): Boolean =
        sessions.removeIf { it.matches(tokenHash, caller, now) }

    override suspend fun deleteExpiredSessions(userId: String, now: Instant) {
        sessions.removeIf { it.userId == userId && !it.expiresAt.isAfter(now) }
    }
}

internal class FakeItemRepository : ItemRepository {
    // key: userId to itemId
    val items = mutableMapOf<Pair<String, String>, StoredItem>()

    // simulates a parallel request that wins between the early check and saving
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

// login tokens of u42 (session s-1) and u43 (session s-2)
internal const val LOGIN_TOKEN = "login-token-u42"
internal const val LOGIN_TOKEN_U43 = "login-token-u43"

internal class FakeAuthService : AuthServiceClient {
    var fail = false
    var calls = 0
    val sessions = mutableMapOf(
        LOGIN_TOKEN to VerifiedSession("u42", "s-1", Instant.parse("2030-01-01T00:00:00Z")),
        LOGIN_TOKEN_U43 to VerifiedSession("u43", "s-2", Instant.parse("2030-01-01T00:00:00Z")),
    )

    override suspend fun verifySession(token: String): VerifiedSession? {
        calls++
        if (fail) throw UpstreamException("auth-service down")
        return sessions[token]
    }
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
        // not a real HMAC, but like one: different unlockKey, different h
        fun h(unlockKey: ByteArray): ByteArray = ByteArray(32) { (unlockKey[it] + 1).toByte() }
    }
}

// alg sets the algorithm byte in the C2 header, like the real service
internal class FakeCryptoService(private val alg: CryptoAlg = CryptoAlg.CHACHA) : CryptoServiceClient {
    var fail = false
    var integrityError = false

    // userId, part, itemId of every call. Synchronized because GET /items decrypts the heads in parallel
    // and a normal list sometimes loses entries
    val calls: MutableList<Triple<String, CryptoPart, String?>> = Collections.synchronizedList(mutableListOf())

    // enough for vault endpoints that only call once
    val calledWith: Triple<String, CryptoPart, String?>? get() = calls.lastOrNull()

    override suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String?): ByteArray {
        calls += Triple(userId, part, itemId)
        if (fail) throw UpstreamException("crypto-service down")
        return c2Of(c1, alg)
    }

    override suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String?): ByteArray {
        calls += Triple(userId, part, itemId)
        if (fail) throw UpstreamException("crypto-service down")
        if (integrityError) throw IntegrityError()
        return c2.copyOfRange(HEADER_SIZE, c2.size - FILLER)
    }

    companion object {
        private const val HEADER_SIZE = 8
        private const val FILLER = 28

        // not real ChaCha20/AES, just recognizable: TLX2 header (with algorithm byte) + c1 + 28 bytes filler = c1 + 36 bytes
        fun c2Of(c1: ByteArray, alg: CryptoAlg = CryptoAlg.CHACHA): ByteArray =
            byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, alg.id, 0x00, 0x01) + c1 + ByteArray(FILLER)
    }
}
