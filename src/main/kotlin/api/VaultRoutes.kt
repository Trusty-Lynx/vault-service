package de.trustylynx.api

import de.trustylynx.common.caller
import de.trustylynx.common.toBase64
import de.trustylynx.common.validateBase64
import de.trustylynx.domain.VaultService
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

// TODO: GET /vault/params, POST /vault/lock implementieren.
fun Route.vaultRoutes(vaultService: VaultService) {
    post("/vault") {
        val caller = call.caller()
        val vault = call.receive<CreateVaultRequest>().validate(caller)
        val vaultToken = vaultService.create(vault)
        call.respond(HttpStatusCode.Created, CreateVaultResponse(vaultToken))
    }

    post("/vault/unlock") {
        val caller = call.caller()
        val unlockKey = validateBase64(call.receive<UnlockVaultRequest>().unlockKey, UNLOCK_KEY_LENGTH)
        val unlocked = vaultService.unlock(caller, unlockKey)
        call.respond(
            UnlockVaultResponse(
                vaultToken = unlocked.vaultToken,
                expiresIn = unlocked.expiresIn.seconds,
                wdek = unlocked.wdek.toBase64(),
            ),
        )
    }
}
