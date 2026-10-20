package de.trustylynx.domain

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.common.AlreadyExists
import de.trustylynx.common.Caller
import de.trustylynx.common.NotFound
import de.trustylynx.common.SecureRandomBytes
import de.trustylynx.common.Unauthorized
import de.trustylynx.common.VaultLocked
import de.trustylynx.persistence.VaultRepository
import de.trustylynx.security.VaultToken
import de.trustylynx.security.VerifierHasher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Clock
import java.time.Duration

/** Ergebnis von GET /vault/params. */
class VaultParams(
    val saltVault: ByteArray,
    val kdf: KdfParams,
)

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
     * GET /vault/params (U1–U2): Salt und Argon2-Parameter, damit der Client aus dem Masterpasswort den unlockKey ableiten kann.
     * Kein Tresor → [NotFound]. Kein Seiteneffekt, auch kein Tresor-Token.
     */
    suspend fun params(caller: Caller): VaultParams {
        val vault = repository.find(caller.userId) ?: throw NotFound()
        return VaultParams(saltVault = vault.saltVault, kdf = vault.kdf)
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
        // Gelegenheit zum Aufräumen: Abgelaufene Tokens dieses Nutzers braucht niemand mehr.
        repository.deleteExpiredSessions(caller.userId, clock.instant())
        return UnlockedVault(vaultToken = token, expiresIn = VaultToken.IDLE_TIMEOUT, wdek = wdek)
    }

    /**
     * Issue #7: Prüft den Tresor-Token für jeden Endpunkt hinter dem Entsperren und verlängert ihn um 15 min.
     * Gültig nur, wenn er zu userId, deviceId UND Login-Session des Aufrufers passt und nicht abgelaufen ist.
     * Endet die Login-Session, passt die sessionId nicht mehr → der Tresor-Token ist damit automatisch ungültig.
     * Fehlt, falsch, fremd oder abgelaufen → [VaultLocked] (401 vault_locked), ohne nach außen zu sagen, was genau.
     */
    suspend fun requireUnlocked(caller: Caller, vaultToken: String?) {
        val tokenHash = hashIfWellFormed(vaultToken) ?: throw VaultLocked()
        val now = clock.instant()
        if (!repository.touchSession(tokenHash, caller, now, now.plus(VaultToken.IDLE_TIMEOUT))) throw VaultLocked()
    }

    /**
     * POST /vault/lock: widerruft den Tresor-Token dieses Geräts. Andere Geräte bleiben entsperrt, der Login bleibt.
     * Schon gesperrt, abgelaufen oder fremd → [VaultLocked]. Laut Doku räumt der Client dann trotzdem lokal auf.
     */
    suspend fun lock(caller: Caller, vaultToken: String?) {
        val tokenHash = hashIfWellFormed(vaultToken) ?: throw VaultLocked()
        if (!repository.deleteSession(tokenHash, caller, clock.instant())) throw VaultLocked()
    }

    private fun hashIfWellFormed(vaultToken: String?): ByteArray? =
        vaultToken?.takeIf(VaultToken::isWellFormed)?.let(VaultToken::hash)

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
