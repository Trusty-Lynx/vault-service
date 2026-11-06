package de.trustylynx.routes

import de.trustylynx.models.CreateVaultRequest
import de.trustylynx.models.UnlockVaultRequest
import de.trustylynx.models.VAULT_TOKEN_HEADER
import de.trustylynx.security.LoginTokenVerifier
import de.trustylynx.services.VaultService
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post

fun Route.vaultRoutes(vaultService: VaultService, loginTokens: LoginTokenVerifier) {
    // login token only, the vault token only exists after unlocking
    get("/vault/params") {
        call.respond(vaultService.params(loginTokens.verify(call)))
    }

    post("/vault") {
        val caller = loginTokens.verify(call)
        val request = call.receive<CreateVaultRequest>()

        val response = vaultService.create(
            caller = caller,
            saltVault = validateBase64(request.salt, SALT_VAULT_LENGTH),
            kdf = validateKdf(request.kdf),
            unlockKey = validateUnlockKey(request.unlockKey),
            wdek = validateWdek(request.wdek),
        )
        call.respond(HttpStatusCode.Created, response)
    }

    post("/vault/unlock") {
        val caller = loginTokens.verify(call)
        val request = call.receive<UnlockVaultRequest>()

        call.respond(vaultService.unlock(caller, validateUnlockKey(request.unlockKey)))
    }

    // only revokes this vault token. 401 vault_locked means it was already locked
    post("/vault/lock") {
        vaultService.lock(loginTokens.verify(call), call.vaultToken())
        call.respond(HttpStatusCode.NoContent)
    }
}

// VaultService checks it
fun ApplicationCall.vaultToken(): String? = request.headers[VAULT_TOKEN_HEADER]
