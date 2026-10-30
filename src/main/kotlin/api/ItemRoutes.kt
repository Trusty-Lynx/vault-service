package de.trustylynx.api

import de.trustylynx.common.Caller
import de.trustylynx.common.itemId
import de.trustylynx.common.toBase64
import de.trustylynx.domain.ItemService
import de.trustylynx.domain.VaultService
import de.trustylynx.security.LoginTokenVerifier
import de.trustylynx.validation.validate
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.put

// Alle Endpunkte hier liegen hinter dem Entsperren: zuerst unlockedCaller(), dann alles andere.
// Die itemId kommt aus dem Header X-Item-Id, nicht aus dem Pfad (Entscheid 2026-10-21).
fun Route.itemRoutes(vaultService: VaultService, itemService: ItemService, loginTokens: LoginTokenVerifier) {
    get("/items") {
        val caller = call.unlockedCaller(vaultService, loginTokens)
        val heads = itemService.listHeads(caller)
        call.respond(ListItemsResponse(heads.map { ItemHeadResponse(id = it.itemId, rev = it.rev, head = it.head.toBase64(), alg = it.alg.wire) }))
    }

    // Nur auf Klick (Anzeigen, Kopieren, Ausfüllen) und immer nur für einen Eintrag.
    get("/items/secret") {
        val caller = call.unlockedCaller(vaultService, loginTokens)
        val secret = itemService.secret(caller, call.itemId())
        call.respond(ItemSecretResponse(data = secret.secret.toBase64(), rev = secret.rev))
    }

    put("/items") {
        val caller = call.unlockedCaller(vaultService, loginTokens)
        val item = call.receive<PutItemRequest>().validate(call.itemId())
        call.respond(PutItemResponse(rev = itemService.put(caller, item)))
    }

    delete("/items") {
        val caller = call.unlockedCaller(vaultService, loginTokens)
        itemService.delete(caller, call.itemId())
        call.respond(HttpStatusCode.NoContent)
    }
}

/**
 * Wer anfragt (Login-Token, #8), und zwar mit gültigem Tresor-Token (#7).
 * Login-Token ungültig → 401 unauthorized, Tresor-Token fehlt oder ungültig → 401 vault_locked.
 * Kommt vor jeder anderen Prüfung, damit ein gesperrter Tresor nichts über Einträge verrät.
 */
private suspend fun ApplicationCall.unlockedCaller(vaultService: VaultService, loginTokens: LoginTokenVerifier): Caller =
    loginTokens.verify(this).also { vaultService.requireUnlocked(it, vaultToken()) }
