package de.trustylynx

import de.trustylynx.api.itemRoutes
import de.trustylynx.api.vaultRoutes
import de.trustylynx.clients.HttpCryptoServiceClient
import de.trustylynx.clients.HttpKeyServiceClient
import de.trustylynx.common.CorsConfig
import de.trustylynx.common.configureCors
import de.trustylynx.common.configureRequestLogging
import de.trustylynx.common.configureSerialization
import de.trustylynx.common.configureStatusPages
import de.trustylynx.common.createDataSource
import de.trustylynx.common.createServiceHttpClient
import de.trustylynx.common.healthRoute
import de.trustylynx.common.isReachable
import de.trustylynx.common.migrateDatabase
import de.trustylynx.domain.ItemService
import de.trustylynx.domain.VaultService
import de.trustylynx.persistence.PostgresItemRepository
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
    migrateDatabase(dataSource)
    val httpClient = createServiceHttpClient()
    monitor.subscribe(ApplicationStopped) {
        httpClient.close()
        dataSource.close()
    }

    val crypto = HttpCryptoServiceClient(httpClient, config.cryptoServiceUrl, config.serviceTokenVault)
    val vaults = VaultService(
        repository = PostgresVaultRepository(dataSource),
        keyService = HttpKeyServiceClient(httpClient, config.keyServiceUrl, config.serviceTokenVault),
        cryptoService = crypto,
    )
    val items = ItemService(PostgresItemRepository(dataSource), crypto)

    configureApp(vaults, items, config.cors) { dataSource.isReachable() }
}

/** Plugins und Routen, getrennt von [module], damit Tests Fakes einsetzen können. */
fun Application.configureApp(
    vaults: VaultService,
    items: ItemService,
    cors: CorsConfig = CorsConfig(),
    isHealthy: suspend () -> Boolean = { true },
) {
    configureRequestLogging()
    // Vor allem anderen, damit auch Fehlerantworten (401, 502 …) die CORS-Header tragen, sonst sieht der Browser nur "CORS error".
    configureCors(cors)
    configureSerialization()
    configureStatusPages()
    routing {
        healthRoute(isHealthy)
        vaultRoutes(vaults)
        itemRoutes(vaults, items)
    }
}
