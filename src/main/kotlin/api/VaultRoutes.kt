package de.trustylynx.api

import de.trustylynx.common.ErrorResponse
import de.trustylynx.common.caller
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

// TODO: GET /vault/params, POST /vault/unlock, POST /vault/lock, PUT /vault/key implementieren.
fun Route.vaultRoutes() {
    post("/vault") {
        val caller = call.caller()
        val vault = call.receive<CreateVaultRequest>().validate(caller)
        // TODO: VaultService.create(vault) aufrufen und 201 mit vaultToken antworten.
        call.application.environment.log.info("POST /vault validated: $vault")
        call.respond(HttpStatusCode.NotImplemented, ErrorResponse("not_implemented"))
    }
}
