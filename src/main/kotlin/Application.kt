package de.trustylynx

import de.trustylynx.api.vaultRoutes
import de.trustylynx.clients.HttpCryptoServiceClient
import de.trustylynx.clients.HttpKeyServiceClient
import de.trustylynx.common.CorsConfig
import de.trustylynx.common.configureCors
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

    configureApp(vaultService, config.cors)
}

/** Plugins und Routen, getrennt von [module], damit Tests Fakes einsetzen können. */
fun Application.configureApp(vaultService: VaultService, cors: CorsConfig = CorsConfig()) {
    // Zuerst, damit auch Fehlerantworten (401, 502 …) die CORS-Header tragen, sonst sieht der Browser nur "CORS error".
    configureCors(cors)
    configureSerialization()
    configureStatusPages()
    routing {
        vaultRoutes(vaultService)
    }
}
