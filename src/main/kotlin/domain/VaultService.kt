package de.trustylynx.domain

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.common.AlreadyExists
import de.trustylynx.common.SecureRandomBytes
import de.trustylynx.persistence.VaultRepository
import de.trustylynx.security.VaultToken
import de.trustylynx.security.VerifierHasher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Clock

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
        val h = keyService.pepperHmac(caller.userId, newVault.unlockKey)
        val vaultVerifier = try {
            // Argon2id mit 19 MiB ist CPU-Arbeit, nicht auf dem Netty-Thread rechnen.
            withContext(Dispatchers.Default) { VerifierHasher.hash(h, saltSVault) }
        } finally {
            h.fill(0)
        }

        // Schicht 2 um den wDEK, gespeichert wird nur wdek_c2.
        val wdekC2 = cryptoService.encrypt(caller.userId, CryptoPart.DEK, newVault.wdek)

        // Netzwerkaufrufe sind durch, jetzt erst die Transaktion.
        val token = VaultToken.generate()
        repository.create(
            Vault(
                userId = caller.userId,
                saltVault = newVault.saltVault,
                kdf = newVault.kdf,
                saltSVault = saltSVault,
                vaultVerifier = vaultVerifier,
                wdekC2 = wdekC2,
            ),
            VaultSession(
                tokenHash = VaultToken.hash(token),
                userId = caller.userId,
                deviceId = caller.deviceId,
                sessionId = caller.sessionId,
                expiresAt = clock.instant().plus(VaultToken.IDLE_TIMEOUT),
            ),
        )
        return token
    }
}
