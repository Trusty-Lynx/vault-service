package de.trustylynx.domain

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.common.AlreadyExists
import de.trustylynx.common.Caller
import de.trustylynx.common.NotFound
import de.trustylynx.common.SecureRandomBytes
import de.trustylynx.common.Unauthorized
import de.trustylynx.persistence.VaultRepository
import de.trustylynx.security.VaultToken
import de.trustylynx.security.VerifierHasher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Clock
import java.time.Duration

/** Ergebnis von POST /vault/unlock. */
class UnlockedVault(
    val vaultToken: String,
    val expiresIn: Duration,
    val wdek: ByteArray,
) {
    override fun toString(): String = "UnlockedVault(expiresIn=$expiresIn)"
}

class VaultService(
    private val repository: VaultRepository,
    private val keyService: KeyServiceClient,
    private val cryptoService: CryptoServiceClient,
    private val clock: Clock = Clock.systemUTC(),
) {
    /** POST /vault: legt den Tresor an und liefert den ersten Tresor-Token (Klartext, nur für die Antwort). */
    suspend fun create(newVault: NewVault): String {
        val caller = newVault.caller

        // Früh abbrechen, damit wir nicht umsonst Key-Service, Argon2 und Crypto-Service bemühen.
        // Die eigentliche Absicherung gegen Doppelanlage ist der Primary Key in create().
        if (repository.exists(caller.userId)) throw AlreadyExists()

        // V3: h vom Key-Service (pepper_vault verlässt ihn nie), dann Argon2id hier.
        val saltSVault = SecureRandomBytes.next(VerifierHasher.SALT_LENGTH)
        val vaultVerifier = withPepperHmac(caller.userId, newVault.unlockKey) { h ->
            VerifierHasher.hash(h, saltSVault)
        }

        // Schicht 2 um den wDEK, gespeichert wird nur wdek_c2.
        val wdekC2 = cryptoService.encrypt(caller.userId, CryptoPart.DEK, newVault.wdek)

        // Netzwerkaufrufe sind durch, jetzt erst die Transaktion.
        val (token, session) = newSession(caller)
        repository.create(
            Vault(
                userId = caller.userId,
                saltVault = newVault.saltVault,
                kdf = newVault.kdf,
                saltSVault = saltSVault,
                vaultVerifier = vaultVerifier,
                wdekC2 = wdekC2,
            ),
            session,
        )
        return token
    }

    /**
     * POST /vault/unlock (U4–U10): prüft das Masterpasswort (als unlockKey) und gibt den wDEK und einen neuen Tresor-Token heraus.
     * Kein Tresor → [NotFound]. Falsches Masterpasswort → [Unauthorized].
     */
    suspend fun unlock(caller: Caller, unlockKey: ByteArray): UnlockedVault {
        val vault = repository.find(caller.userId) ?: throw NotFound()

        // U5 + U6: h vom Key-Service, Argon2id hier, Vergleich in konstanter Zeit.
        val matches = withPepperHmac(caller.userId, unlockKey) { h ->
            VerifierHasher.matches(h, vault.saltSVault, vault.vaultVerifier)
        }
        // Keine Unterscheidung nach außen, warum es nicht passt. Rate-Limit ist gestrichen.
        if (!matches) throw Unauthorized()

        // U7–U9: Schicht 2 vom wDEK abnehmen. Ein Ticket braucht es dafür nicht.
        val wdek = cryptoService.decrypt(caller.userId, CryptoPart.DEK, vault.wdekC2)

        val (token, session) = newSession(caller)
        repository.createSession(session)
        return UnlockedVault(vaultToken = token, expiresIn = VaultToken.IDLE_TIMEOUT, wdek = wdek)
    }

    /**
     * Holt h = HMAC(pepper_vault, unlockKey) vom Key-Service und rechnet [block] damit.
     * [block] läuft auf Dispatchers.Default (Argon2id mit 19 MiB ist CPU-Arbeit, nicht auf dem Netty-Thread rechnen).
     * h wird danach mit Nullen überschrieben.
     */
    private suspend fun <T> withPepperHmac(userId: String, unlockKey: ByteArray, block: (ByteArray) -> T): T {
        val h = keyService.pepperHmac(userId, unlockKey)
        return try {
            withContext(Dispatchers.Default) { block(h) }
        } finally {
            h.fill(0)
        }
    }

    /** Neuer Tresor-Token für dieses Gerät und diese Login-Session. Der Klartext geht nur in die Antwort. */
    private fun newSession(caller: Caller): Pair<String, VaultSession> {
        val token = VaultToken.generate()
        return token to VaultSession(
            tokenHash = VaultToken.hash(token),
            userId = caller.userId,
            deviceId = caller.deviceId,
            sessionId = caller.sessionId,
            expiresAt = clock.instant().plus(VaultToken.IDLE_TIMEOUT),
        )
    }
}
