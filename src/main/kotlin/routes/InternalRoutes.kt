package de.trustylynx.routes

import de.trustylynx.models.VerifyUnlockedRequest
import de.trustylynx.security.requireServiceToken
import de.trustylynx.services.VaultService
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

// only for other services, every route has to check the service token first
fun Route.internalRoutes(vaultService: VaultService, breachToken: String) {
    require(breachToken.isNotEmpty()) { "breachToken must not be empty" }

    // breach service asks if the vault is unlocked for this login session: 204 = yes, 401 vault_locked = no.
    // same check as before GET /items, so it also extends the vault token
    post("/internal/vault/unlocked") {
        // before reading the body: without a valid service token it's always 403, even with a broken body
        call.requireServiceToken(breachToken)

        val request = call.receive<VerifyUnlockedRequest>()
        val caller = validateCaller(request.userId, request.sessionId)
        vaultService.requireUnlocked(caller, request.vaultToken)
        call.respond(HttpStatusCode.NoContent)
    }
}
