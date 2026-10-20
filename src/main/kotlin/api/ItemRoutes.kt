package de.trustylynx.api

import de.trustylynx.common.Caller
import de.trustylynx.common.caller
import de.trustylynx.common.itemId
import de.trustylynx.domain.ItemService
import de.trustylynx.domain.VaultService
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.put

// Alle Endpunkte hier liegen hinter dem Entsperren: zuerst unlockedCaller(), dann alles andere.
// Die itemId kommt aus dem Header X-Item-Id, nicht aus dem Pfad (Entscheid 2026-10-21).
fun Route.itemRoutes(vaultService: VaultService, itemService: ItemService) {
    put("/items") {
        val caller = call.unlockedCaller(vaultService)
        val item = call.receive<PutItemRequest>().validate(call.itemId())
        call.respond(PutItemResponse(rev = itemService.put(caller, item)))
    }
}

/**
 * Wer anfragt, und zwar mit gültigem Tresor-Token (Issue #7). Fehlt oder ungültig → 401 vault_locked.
 * Kommt vor jeder anderen Prüfung, damit ein gesperrter Tresor nichts über Einträge verrät.
 */
private suspend fun ApplicationCall.unlockedCaller(vaultService: VaultService): Caller =
    caller().also { vaultService.requireUnlocked(it, vaultToken()) }
