package de.trustylynx.api

import de.trustylynx.common.caller
import de.trustylynx.domain.VaultService
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

// TODO: GET /vault/params, POST /vault/unlock, POST /vault/lock implementieren.
fun Route.vaultRoutes(vaultService: VaultService) {
    post("/vault") {
        val caller = call.caller()
        val vault = call.receive<CreateVaultRequest>().validate(caller)
        val vaultToken = vaultService.create(vault)
        call.respond(HttpStatusCode.Created, CreateVaultResponse(vaultToken))
    }
}
