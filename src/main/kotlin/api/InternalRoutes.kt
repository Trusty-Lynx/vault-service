package de.trustylynx.api

import de.trustylynx.common.requireServiceToken
import de.trustylynx.domain.VaultService
import de.trustylynx.validation.validate
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post

/** Routen nur für andere Services. Jede Route muss zuerst den Service-Token prüfen. Wie im auth-service. */
fun Route.internalRoutes(vaultService: VaultService, breachToken: String) {
    require(breachToken.isNotEmpty()) { "breachToken must not be empty" }

    // Breach-Service: Ist der Tresor dieses Nutzers auf diesem Gerät entsperrt? 204 = ja, 401 vault_locked = nein.
    // Gleiche Prüfung wie vor GET /items, verlängert also auch die Leerlaufzeit des Tresor-Tokens.
    post("/internal/vault/unlocked") {
        // Vor dem Body prüfen: ohne gültigen Service-Token gibt es immer 403, auch bei kaputtem Body.
        call.requireServiceToken(breachToken)

        val request = call.receive<VerifyUnlockedRequest>()
        vaultService.requireUnlocked(request.validate(), request.vaultToken)
        call.respond(HttpStatusCode.NoContent)
    }
}
