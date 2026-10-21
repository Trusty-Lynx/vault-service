package de.trustylynx.api

import de.trustylynx.common.VAULT_TOKEN_HEADER
import de.trustylynx.common.caller
import de.trustylynx.common.toBase64
import de.trustylynx.domain.VaultService
import de.trustylynx.validation.validate
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post

fun Route.vaultRoutes(vaultService: VaultService) {
    // Nur Login-Token (bzw. vorerst Caller-Header), kein Tresor-Token: den gibt es erst nach dem Entsperren.
    get("/vault/params") {
        val params = vaultService.params(call.caller())
        call.respond(VaultParamsResponse(salt = params.saltVault.toBase64(), kdf = params.kdf))
    }

    post("/vault") {
        val caller = call.caller()
        val vault = call.receive<CreateVaultRequest>().validate(caller)
        val vaultToken = vaultService.create(vault)
        call.respond(HttpStatusCode.Created, CreateVaultResponse(vaultToken))
    }

    post("/vault/unlock") {
        val caller = call.caller()
        val unlockKey = call.receive<UnlockVaultRequest>().validate()
        val unlocked = vaultService.unlock(caller, unlockKey)
        call.respond(
            UnlockVaultResponse(
                vaultToken = unlocked.vaultToken,
                expiresIn = unlocked.expiresIn.seconds,
                wdek = unlocked.wdek.toBase64(),
            ),
        )
    }

    // Widerruft nur den Tresor-Token dieses Geräts. 401 vault_locked heißt: war schon gesperrt.
    post("/vault/lock") {
        vaultService.lock(call.caller(), call.vaultToken())
        call.respond(HttpStatusCode.NoContent)
    }
}

/** Der Tresor-Token aus `X-Vault-Token`, oder null. Geprüft wird er im VaultService. */
fun ApplicationCall.vaultToken(): String? = request.headers[VAULT_TOKEN_HEADER]
