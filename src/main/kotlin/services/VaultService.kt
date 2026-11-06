package de.trustylynx.services

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.models.AlreadyExists
import de.trustylynx.models.Caller
import de.trustylynx.models.CreateVaultResponse
import de.trustylynx.models.KdfParams
import de.trustylynx.models.NotFound
import de.trustylynx.models.Unauthorized
import de.trustylynx.models.UnlockVaultResponse
import de.trustylynx.models.Vault
import de.trustylynx.models.VaultLocked
import de.trustylynx.models.VaultParamsResponse
import de.trustylynx.models.VaultSession
import de.trustylynx.repositories.VaultRepository
import de.trustylynx.security.VaultToken
import de.trustylynx.security.VerifierHasher
import de.trustylynx.security.secureRandomBytes
import de.trustylynx.security.toBase64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Clock

class VaultService(
    private val repository: VaultRepository,
    private val keyService: KeyServiceClient,
    private val cryptoService: CryptoServiceClient,
    private val clock: Clock = Clock.systemUTC(),
) {
    suspend fun create(caller: Caller, saltVault: ByteArray, kdf: KdfParams, unlockKey: ByteArray, wdek: ByteArray): CreateVaultResponse {
        // stop early so we don't call the key service, Argon2 and the crypto service for nothing.
        // The real protection against creating it twice is the primary key in repository.create()
        if (repository.exists(caller.userId)) throw AlreadyExists()

        val saltSVault = secureRandomBytes(VerifierHasher.SALT_LENGTH)
        val vaultVerifier = withPepperHmac(caller.userId, unlockKey) { h ->
            VerifierHasher.hash(h, saltSVault)
        }

        val wdekC2 = cryptoService.encrypt(caller.userId, CryptoPart.DEK, wdek)

        // network calls are done, only now the transaction
        val token = VaultToken.generate()
        repository.create(
            Vault(
                userId = caller.userId,
                saltVault = saltVault,
                kdf = kdf,
                saltSVault = saltSVault,
                vaultVerifier = vaultVerifier,
                wdekC2 = wdekC2,
            ),
            newSession(caller, token),
        )
        return CreateVaultResponse(vaultToken = token)
    }

    suspend fun params(caller: Caller): VaultParamsResponse {
        val vault = repository.find(caller.userId) ?: throw NotFound()
        return VaultParamsResponse(salt = vault.saltVault.toBase64(), kdf = vault.kdf)
    }

    suspend fun unlock(caller: Caller, unlockKey: ByteArray): UnlockVaultResponse {
        val vault = repository.find(caller.userId) ?: throw NotFound()

        val matches = withPepperHmac(caller.userId, unlockKey) { h ->
            VerifierHasher.matches(h, vault.saltSVault, vault.vaultVerifier)
        }
        // don't tell the outside why it didn't match
        if (!matches) throw Unauthorized()

        val wdek = cryptoService.decrypt(caller.userId, CryptoPart.DEK, vault.wdekC2)

        val token = VaultToken.generate()
        repository.createSession(newSession(caller, token))
        // good moment to clean up, nobody needs this user's expired tokens anymore
        repository.deleteExpiredSessions(caller.userId, clock.instant())
        return UnlockVaultResponse(
            vaultToken = token,
            expiresIn = VaultToken.IDLE_TIMEOUT.seconds,
            wdek = wdek.toBase64(),
        )
    }

    // The token has to match userId and the login session. When the login session ends, the sessionId
    // no longer matches, so the vault token is dead too. Every failure is the same VaultLocked, we don't say why
    suspend fun requireUnlocked(caller: Caller, vaultToken: String?) {
        val tokenHash = hashIfWellFormed(vaultToken) ?: throw VaultLocked()
        val now = clock.instant()
        if (!repository.touchSession(tokenHash, caller, now, now.plus(VaultToken.IDLE_TIMEOUT))) throw VaultLocked()
    }

    // only this vault token, the login stays as it is
    suspend fun lock(caller: Caller, vaultToken: String?) {
        val tokenHash = hashIfWellFormed(vaultToken) ?: throw VaultLocked()
        if (!repository.deleteSession(tokenHash, caller, clock.instant())) throw VaultLocked()
    }

    private fun hashIfWellFormed(vaultToken: String?): ByteArray? {
        if (vaultToken == null || !VaultToken.isWellFormed(vaultToken)) return null
        return VaultToken.hash(vaultToken)
    }

    // Argon2id is CPU work, so it runs on Dispatchers.Default and not on a Netty thread. h is zeroed afterwards
    private suspend fun <T> withPepperHmac(userId: String, unlockKey: ByteArray, block: (ByteArray) -> T): T {
        val h = keyService.pepperHmac(userId, unlockKey)
        return try {
            withContext(Dispatchers.Default) { block(h) }
        } finally {
            h.fill(0)
        }
    }

    // only the hash goes into the DB, the plain token only into the response
    private fun newSession(caller: Caller, token: String) = VaultSession(
        tokenHash = VaultToken.hash(token),
        userId = caller.userId,
        sessionId = caller.sessionId,
        expiresAt = clock.instant().plus(VaultToken.IDLE_TIMEOUT),
    )
}
