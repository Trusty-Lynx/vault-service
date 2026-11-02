package de.trustylynx

import de.trustylynx.api.graphQlRoutes
import de.trustylynx.api.internalRoutes
import de.trustylynx.api.itemRoutes
import de.trustylynx.api.vaultRoutes
import de.trustylynx.clients.CryptoAlg
import de.trustylynx.clients.CryptoServices
import de.trustylynx.clients.HttpAuthServiceClient
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
import de.trustylynx.security.LoginTokenVerifier
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

    // wDEK immer über ChaCha, Einträge über den Service, den der Nutzer pro Eintrag wählt.
    val chacha = HttpCryptoServiceClient(httpClient, config.cryptoServiceUrl, config.serviceTokenVault, CryptoAlg.CHACHA)
    val aes = HttpCryptoServiceClient(httpClient, config.cryptoAesServiceUrl, config.serviceTokenVault, CryptoAlg.AES)
    val vaults = VaultService(
        repository = PostgresVaultRepository(dataSource),
        keyService = HttpKeyServiceClient(httpClient, config.keyServiceUrl, config.serviceTokenVault),
        cryptoService = chacha,
    )
    val items = ItemService(PostgresItemRepository(dataSource), CryptoServices(aes = aes, chacha = chacha))
    val loginTokens = LoginTokenVerifier(HttpAuthServiceClient(httpClient, config.authServiceUrl, config.serviceTokenGateway))

    configureApp(vaults, items, loginTokens, config.cors, config.serviceTokenBreach) { dataSource.isReachable() }
}

/** Plugins und Routen, getrennt von [module], damit Tests Fakes einsetzen können. */
fun Application.configureApp(
    vaults: VaultService,
    items: ItemService,
    loginTokens: LoginTokenVerifier,
    cors: CorsConfig = CorsConfig(),
    // Leer = keine internen Routen. In module() kommt er immer aus SERVICE_TOKEN_BREACH (Pflicht in Prod).
    breachToken: String = "",
    isHealthy: suspend () -> Boolean = { true },
) {
    configureRequestLogging()
    // Vor allem anderen, damit auch Fehlerantworten (401, 502 …) die CORS-Header tragen, sonst sieht der Browser nur "CORS error".
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
