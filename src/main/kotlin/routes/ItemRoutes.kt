package de.trustylynx.routes

import de.trustylynx.models.Caller
import de.trustylynx.models.ListItemsResponse
import de.trustylynx.models.PutItemRequest
import de.trustylynx.security.LoginTokenVerifier
import de.trustylynx.services.ItemService
import de.trustylynx.services.VaultService
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.put

fun Route.itemRoutes(vaultService: VaultService, itemService: ItemService, loginTokens: LoginTokenVerifier) {
    get("/items") {
        val caller = call.unlockedCaller(vaultService, loginTokens)
        call.respond(ListItemsResponse(itemService.listHeads(caller)))
    }

    // only on click (show, copy, fill in) and always for one item only
    get("/items/secret") {
        val caller = call.unlockedCaller(vaultService, loginTokens)
        call.respond(itemService.secret(caller, call.itemId()))
    }

    put("/items") {
        val caller = call.unlockedCaller(vaultService, loginTokens)
        val request = call.receive<PutItemRequest>()

        val response = itemService.put(
            caller = caller,
            itemId = call.itemId(),
            rev = validateRev(request.rev),
            head = validateC1(request.head, "head"),
            secret = validateC1(request.secret, "secret"),
            alg = validateAlg(request.alg),
        )
        call.respond(response)
    }

    delete("/items") {
        val caller = call.unlockedCaller(vaultService, loginTokens)
        itemService.delete(caller, call.itemId())
        call.respond(HttpStatusCode.NoContent)
    }
}

// comes before every other check, so a locked vault doesn't reveal anything about its items
private suspend fun ApplicationCall.unlockedCaller(vaultService: VaultService, loginTokens: LoginTokenVerifier): Caller {
    val caller = loginTokens.verify(this)
    vaultService.requireUnlocked(caller, vaultToken())
    return caller
}
