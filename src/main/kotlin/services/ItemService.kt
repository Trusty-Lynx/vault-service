package de.trustylynx.services

import de.trustylynx.clients.CryptoAlg
import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServices
import de.trustylynx.models.Caller
import de.trustylynx.models.ItemHeadResponse
import de.trustylynx.models.ItemSecretResponse
import de.trustylynx.models.NotFound
import de.trustylynx.models.PutItemResponse
import de.trustylynx.models.RevConflict
import de.trustylynx.models.StoredItem
import de.trustylynx.repositories.ItemRepository
import de.trustylynx.security.toBase64
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

private const val MAX_PARALLEL_DECRYPTS = 8

// The vault token is already checked in the routes. We never see plain text: head and secret arrive as C1
// from the client, we only store C2.
class ItemService(
    private val repository: ItemRepository,
    private val cryptoServices: CryptoServices,
) {
    // rev 1 creates the item, rev = current + 1 changes it, anything else is a RevConflict and nothing gets overwritten
    suspend fun put(caller: Caller, itemId: String, rev: Int, head: ByteArray, secret: ByteArray, alg: CryptoAlg): PutItemResponse {
        // check early, so a conflict doesn't cost two crypto service calls for nothing
        val current = repository.currentRev(caller.userId, itemId) ?: 0
        if (rev != current + 1) throw RevConflict(current)

        // network calls before writing to the DB. If the user switches the service while editing,
        // we just encrypt again (C1 is new anyway)
        val stored = StoredItem(
            itemId = itemId,
            rev = rev,
            headC2 = cryptoServices.encrypt(alg, caller.userId, CryptoPart.HEAD, head, itemId),
            secretC2 = cryptoServices.encrypt(alg, caller.userId, CryptoPart.SECRET, secret, itemId),
        )

        // the real protection is the atomic SQL, if another device saved in the meantime it's a 409
        val saved = if (rev == 1) {
            repository.insert(caller.userId, stored)
        } else {
            repository.update(caller.userId, stored, previousRev = rev - 1)
        }
        if (!saved) throw RevConflict(repository.currentRev(caller.userId, itemId) ?: 0)
        return PutItemResponse(rev = rev)
    }

    // A tampered head fails the whole list with IntegrityError, and if one of the crypto services is down
    // the whole list fails with crypto_unavailable. Kept simple on purpose
    suspend fun listHeads(caller: Caller): List<ItemHeadResponse> {
        val stored = repository.listHeads(caller.userId)
        // one decrypt per head, in parallel but limited, so 500 items don't turn into 500 requests at once
        val limit = Semaphore(MAX_PARALLEL_DECRYPTS)
        return coroutineScope {
            stored.map { item ->
                async {
                    limit.withPermit {
                        val head = cryptoServices.decrypt(caller.userId, CryptoPart.HEAD, item.headC2, item.itemId)
                        ItemHeadResponse(
                            id = item.itemId,
                            rev = item.rev,
                            head = head.toBase64(),
                            alg = cryptoServices.algOf(item.headC2).wire,
                        )
                    }
                }
            }.awaitAll()
        }
    }

    // NotFound also when the item belongs to someone else
    suspend fun secret(caller: Caller, itemId: String): ItemSecretResponse {
        val stored = repository.findSecret(caller.userId, itemId) ?: throw NotFound()
        val secret = cryptoServices.decrypt(caller.userId, CryptoPart.SECRET, stored.secretC2, itemId)
        return ItemSecretResponse(data = secret.toBase64(), rev = stored.rev)
    }

    suspend fun delete(caller: Caller, itemId: String) {
        if (!repository.delete(caller.userId, itemId)) throw NotFound()
    }
}
