package de.trustylynx

import de.trustylynx.common.DbConfig
import de.trustylynx.common.envOrDev

/** Alle Umgebungsvariablen des vault-service an einer Stelle. */
class AppConfig(
    val db: DbConfig,
    val keyServiceUrl: String,
    val cryptoServiceUrl: String,
    val serviceTokenVault: String,
) {
    // Ohne Service-Token, damit er nie im Log landet.
    override fun toString(): String =
        "AppConfig(db=$db, keyServiceUrl=$keyServiceUrl, cryptoServiceUrl=$cryptoServiceUrl)"

    companion object {
        fun fromEnv() = AppConfig(
            db = DbConfig(
                url = envOrDev("DB_URL", "jdbc:postgresql://localhost:5435/vault"),
                user = envOrDev("DB_USER", "dev"),
                password = envOrDev("DB_PASSWORD", "dev"),
                poolName = "vault-db",
            ),
            // Lokal läuft der Key-Service auf 7492 (siehe key-service/docker-compose.yml).
            keyServiceUrl = envOrDev("KEY_SERVICE_URL", "http://localhost:7492"),
            // Crypto-Service 1 (AES). Port lokal noch nicht festgelegt, 7494 ist ein Platzhalter.
            cryptoServiceUrl = envOrDev("CRYPTO_SERVICE_URL", "http://localhost:7494"),
            // Muss im Key-Service als VAULT_SERVICE_TOKEN hinterlegt sein (und im Crypto-Service).
            serviceTokenVault = envOrDev("SERVICE_TOKEN_VAULT", "dev-service-token-vault"),
        )
    }
}
