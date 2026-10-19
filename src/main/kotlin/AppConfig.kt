package de.trustylynx

import de.trustylynx.common.DbConfig
import de.trustylynx.common.envOrDev

/** Alle Umgebungsvariablen des vault-service an einer Stelle. */
class AppConfig(
    val db: DbConfig,
) {
    companion object {
        fun fromEnv() = AppConfig(
            db = DbConfig(
                url = envOrDev("DB_URL", "jdbc:postgresql://localhost:5435/vault"),
                user = envOrDev("DB_USER", "dev"),
                password = envOrDev("DB_PASSWORD", "dev"),
                poolName = "vault-db",
            ),
        )
    }
}
