package de.trustylynx.domain

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServices
import de.trustylynx.common.Caller
import de.trustylynx.common.NotFound
import de.trustylynx.common.RevConflict
import de.trustylynx.persistence.ItemRepository
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

/**
 * Einträge im Tresor. Der Tresor-Token ist hier schon geprüft (VaultService.requireUnlocked in den Routen).
 * Der Server sieht nie Klartext: Kopf und Geheimnis kommen als C1 vom Client, gespeichert wird nur C2.
 * Schicht 2 macht pro Eintrag Crypto-Service 1 (AES) oder 2 (ChaCha), siehe [CryptoServices].
 */
class ItemService(
    private val repository: ItemRepository,
    private val cryptoServices: CryptoServices,
) {
    /**
     * PUT /items (E2–E11): legt einen Eintrag an (rev 1) oder ändert ihn (rev = aktuelle + 1). Liefert die gespeicherte rev.
     * Passt rev nicht → [RevConflict] (409), es wird nichts still überschrieben.
     */
    suspend fun put(caller: Caller, item: NewItem): Int {
        // Früh prüfen, damit wir bei einem Konflikt nicht umsonst zweimal den Crypto-Service bemühen.
        val current = repository.currentRev(caller.userId, item.itemId) ?: 0
        if (item.rev != current + 1) throw RevConflict(current)

        // E5–E9: Schicht 2 um beide Teile, beide beim gewählten Service. Netzwerkaufrufe vor dem Schreiben in die DB.
        // Wechselt der Nutzer beim Bearbeiten den Service, wird einfach neu verschlüsselt (C1 ist ohnehin frisch).
        val stored = StoredItem(
            itemId = item.itemId,
            rev = item.rev,
            headC2 = cryptoServices.encrypt(item.alg, caller.userId, CryptoPart.HEAD, item.head, item.itemId),
            secretC2 = cryptoServices.encrypt(item.alg, caller.userId, CryptoPart.SECRET, item.secret, item.itemId),
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

    /**
     * GET /items (D7): Köpfe aller Einträge, Schicht 2 abgenommen, also C1. Keine Passwörter.
     * Teil h braucht kein Ticket. Ein manipulierter Kopf → IntegrityError (500) für die ganze Liste.
     * Ist einer der beiden Crypto-Services weg, scheitert die ganze Liste mit crypto_unavailable (bewusst einfach gehalten).
     */
    suspend fun listHeads(caller: Caller): List<ItemHead> {
        val stored = repository.listHeads(caller.userId)
        // Pro Kopf ein decrypt. Parallel, aber begrenzt, damit 500 Einträge nicht 500 gleichzeitige Anfragen werden.
        val limit = Semaphore(MAX_PARALLEL_DECRYPTS)
        return coroutineScope {
            stored.map { item ->
                async {
                    limit.withPermit {
                        ItemHead(
                            itemId = item.itemId,
                            rev = item.rev,
                            head = cryptoServices.decrypt(caller.userId, CryptoPart.HEAD, item.headC2, item.itemId),
                            alg = cryptoServices.algOf(item.headC2),
                        )
                    }
                }
            }.awaitAll()
        }
    }

    /**
     * GET /items/secret (D6–D12): das Geheimnis (Passwort) EINES Eintrags als C1, mit rev für die AAD.
     * Gibt es den Eintrag nicht (oder gehört er jemand anderem) → [NotFound].
     *
     * Guard und Ticket sind gestrichen (D3–D5 entfallen). ACHTUNG: Der ChaCha-Service verlangt für Teil s
     * noch ein Guard-Ticket und antwortet sonst 403 → bei uns 502, bis die Prüfung dort entfernt ist.
     */
    suspend fun secret(caller: Caller, itemId: String): ItemSecret {
        val stored = repository.findSecret(caller.userId, itemId) ?: throw NotFound()
        val secret = cryptoServices.decrypt(caller.userId, CryptoPart.SECRET, stored.secretC2, itemId)
        return ItemSecret(rev = stored.rev, secret = secret)
    }

    /**
     * DELETE /items: löscht einen Eintrag. Gibt es ihn nicht (auch beim zweiten Löschen) → [NotFound].
     * Schutzklassen und trusted-Geräte sind gestrichen, deshalb keine weiteren Prüfungen.
     * Offen laut Doku: erwartete rev mitschicken, damit kein inzwischen geänderter Eintrag gelöscht wird.
     */
    suspend fun delete(caller: Caller, itemId: String) {
        if (!repository.delete(caller.userId, itemId)) throw NotFound()
    }

    private companion object {
        const val MAX_PARALLEL_DECRYPTS = 8
    }
}
