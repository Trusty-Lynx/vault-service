package de.trustylynx

import de.trustylynx.clients.CryptoAlg
import de.trustylynx.clients.CryptoServices
import de.trustylynx.clients.HttpAuthServiceClient
import de.trustylynx.clients.HttpCryptoServiceClient
import de.trustylynx.clients.HttpKeyServiceClient
import de.trustylynx.clients.createServiceHttpClient
import de.trustylynx.plugins.CorsConfig
import de.trustylynx.plugins.configureCors
import de.trustylynx.plugins.configureRequestLogging
import de.trustylynx.plugins.configureSerialization
import de.trustylynx.plugins.configureStatusPages
import de.trustylynx.repositories.PostgresItemRepository
import de.trustylynx.repositories.PostgresVaultRepository
import de.trustylynx.repositories.createDataSource
import de.trustylynx.repositories.isReachable
import de.trustylynx.repositories.migrateDatabase
import de.trustylynx.routes.graphQlRoutes
import de.trustylynx.routes.healthRoute
import de.trustylynx.routes.internalRoutes
import de.trustylynx.routes.itemRoutes
import de.trustylynx.routes.vaultRoutes
import de.trustylynx.security.LoginTokenVerifier
import de.trustylynx.services.ItemService
import de.trustylynx.services.VaultService
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopped
import io.ktor.server.netty.EngineMain
import io.ktor.server.routing.routing

fun main(args: Array<String>) {
    EngineMain.main(args)
}

fun Application.module() {
    val config = AppConfig.fromEnv()

    val dataSource = createDataSource(config.db)
    migrateDatabase(dataSource)
    val httpClient = createServiceHttpClient()
    monitor.subscribe(ApplicationStopped) {
        httpClient.close()
        dataSource.close()
    }

    // the wDEK always goes through ChaCha, items through whichever service the user picked
    val chacha = HttpCryptoServiceClient(httpClient, config.cryptoServiceUrl, config.serviceTokenVault, CryptoAlg.CHACHA)
    val aes = HttpCryptoServiceClient(httpClient, config.cryptoAesServiceUrl, config.serviceTokenAes, CryptoAlg.AES)
    val vaults = VaultService(
        repository = PostgresVaultRepository(dataSource),
        keyService = HttpKeyServiceClient(httpClient, config.keyServiceUrl, config.serviceTokenVault),
        cryptoService = chacha,
    )
    val items = ItemService(PostgresItemRepository(dataSource), CryptoServices(aes = aes, chacha = chacha))
    val loginTokens = LoginTokenVerifier(HttpAuthServiceClient(httpClient, config.authServiceUrl, config.serviceTokenGateway))

    configureApp(vaults, items, loginTokens, config.cors, config.serviceTokenBreach) { dataSource.isReachable() }
}

fun Application.configureApp(
    vaults: VaultService,
    items: ItemService,
    loginTokens: LoginTokenVerifier,
    cors: CorsConfig = CorsConfig(),
    // empty means no internal routes
    breachToken: String = "",
    isHealthy: suspend () -> Boolean = { true },
) {
    configureRequestLogging()
    // before everything else so error responses (401, 502, ...) get CORS headers too,
    // otherwise the browser only shows "CORS error"
    configureCors(cors)
    configureSerialization()
    configureStatusPages()
    routing {
        healthRoute(isHealthy)
        vaultRoutes(vaults, loginTokens)
        itemRoutes(vaults, items, loginTokens)
        graphQlRoutes(vaults, items, loginTokens)
        if (breachToken.isNotEmpty()) internalRoutes(vaults, breachToken)
    }
}
