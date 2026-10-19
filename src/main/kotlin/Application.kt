package de.trustylynx

import de.trustylynx.api.vaultRoutes
import de.trustylynx.common.configureSerialization
import de.trustylynx.common.configureStatusPages
import de.trustylynx.common.createDataSource
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
    monitor.subscribe(ApplicationStopped) {
        dataSource.close()
    }

    // TODO: Repository, Clients und VaultService aus dataSource bauen und an configureApp übergeben.
    configureApp()
}

/** Plugins und Routen, getrennt von [module], damit Tests Fakes einsetzen können. */
fun Application.configureApp() {
    configureSerialization()
    configureStatusPages()
    routing {
        vaultRoutes()
    }
}
