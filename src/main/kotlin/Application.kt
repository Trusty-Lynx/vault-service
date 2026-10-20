package de.trustylynx

import de.trustylynx.api.vaultRoutes
import de.trustylynx.clients.HttpCryptoServiceClient
import de.trustylynx.clients.HttpKeyServiceClient
import de.trustylynx.common.configureSerialization
import de.trustylynx.common.configureStatusPages
import de.trustylynx.common.createDataSource
import de.trustylynx.common.createServiceHttpClient
import de.trustylynx.domain.VaultService
import de.trustylynx.persistence.PostgresVaultRepository
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopped
import io.ktor.server.netty.EngineMain
import io.ktor.server.routing.routing

fun main(args: Array<String>) {
    EngineMain.main(args)
}

/** Einziger Ort, an dem Abhängigkeiten gebaut und verdrahtet werden. */
fun Application.module() {
    val config = AppConfig.fromEnv()

    val dataSource = createDataSource(config.db)
    val http = createServiceHttpClient()
    monitor.subscribe(ApplicationStopped) {
        http.close()
        dataSource.close()
    }

    val vaultService = VaultService(
        repository = PostgresVaultRepository(dataSource),
        keyService = HttpKeyServiceClient(http, config.keyServiceUrl, config.serviceTokenVault),
        cryptoService = HttpCryptoServiceClient(http, config.cryptoServiceUrl, config.serviceTokenVault),
    )

    // TODO(#8): Sobald der Auth-Service den Vault für /internal/sessions/verify zulässt, hier
    //  LoginTokenVerifier(HttpAuthServiceClient(http, config.authServiceUrl, config.serviceTokenVault)) bauen
    //  und in den Routen statt call.caller() verwenden.
    configureApp(vaultService)
}

/** Plugins und Routen, getrennt von [module], damit Tests Fakes einsetzen können. */
fun Application.configureApp(vaultService: VaultService) {
    configureSerialization()
    configureStatusPages()
    routing {
        vaultRoutes(vaultService)
    }
}
