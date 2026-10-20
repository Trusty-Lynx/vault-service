package de.trustylynx.domain

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.common.Caller
import de.trustylynx.common.RevConflict
import de.trustylynx.persistence.ItemRepository

/**
 * Einträge im Tresor. Der Tresor-Token ist hier schon geprüft (VaultService.requireUnlocked in den Routen).
 * Der Server sieht nie Klartext: Kopf und Geheimnis kommen als C1 vom Client, gespeichert wird nur C2.
 */
class ItemService(
    private val repository: ItemRepository,
    private val cryptoService: CryptoServiceClient,
) {
    /**
     * PUT /items (E2–E11): legt einen Eintrag an (rev 1) oder ändert ihn (rev = aktuelle + 1). Liefert die gespeicherte rev.
     * Passt rev nicht → [RevConflict] (409), es wird nichts still überschrieben.
     */
    suspend fun put(caller: Caller, item: NewItem): Int {
        // Früh prüfen, damit wir bei einem Konflikt nicht umsonst zweimal den Crypto-Service bemühen.
        val current = repository.currentRev(caller.userId, item.itemId) ?: 0
        if (item.rev != current + 1) throw RevConflict(current)

        // E5–E9: Schicht 2 um beide Teile. Netzwerkaufrufe vor dem Schreiben in die DB.
        val stored = StoredItem(
            itemId = item.itemId,
            rev = item.rev,
            headC2 = cryptoService.encrypt(caller.userId, CryptoPart.HEAD, item.head, item.itemId),
            secretC2 = cryptoService.encrypt(caller.userId, CryptoPart.SECRET, item.secret, item.itemId),
        )

        // E10: Die eigentliche Absicherung ist atomar im SQL. Hat inzwischen ein anderes Gerät gespeichert → 409.
        val saved = if (item.rev == 1) {
            repository.insert(caller.userId, stored)
        } else {
            repository.update(caller.userId, stored, previousRev = item.rev - 1)
        }
        if (!saved) throw RevConflict(repository.currentRev(caller.userId, item.itemId) ?: 0)
        return item.rev
    }
}
