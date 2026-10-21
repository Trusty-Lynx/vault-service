package de.trustylynx

import de.trustylynx.common.CorsConfig
import de.trustylynx.common.DbConfig
import de.trustylynx.common.env
import de.trustylynx.common.envOrDev

/** Alle Umgebungsvariablen des vault-service an einer Stelle. */
class AppConfig(
    val db: DbConfig,
    val keyServiceUrl: String,
    val cryptoServiceUrl: String,
    val authServiceUrl: String,
    val serviceTokenVault: String,
    val cors: CorsConfig,
) {
    // Ohne Service-Token, damit er nie im Log landet.
    override fun toString(): String =
        "AppConfig(db=$db, keyServiceUrl=$keyServiceUrl, cryptoServiceUrl=$cryptoServiceUrl, cors=$cors, authServiceUrl=$authServiceUrl)"
        

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
            // Crypto-Service 2 (ChaCha20), Server: https://chacha50poly1305.nexvent.de. Lokal 7494 ist ein Platzhalter.
            cryptoServiceUrl = envOrDev("CRYPTO_SERVICE_URL", "http://localhost:7494"),
            // Für POST /internal/sessions/verify (#8). Default ist der Container im trustylynx-net, lokal z. B. http://localhost:7491.
            // Bewusst nicht envOrDev: Solange #8 nicht in den Routen hängt, soll ein fehlender Wert den Start nicht verhindern.
            authServiceUrl = env("AUTH_SERVICE_URL", "http://auth-service:8080"),
            // Muss im Key-Service als VAULT_SERVICE_TOKEN hinterlegt sein (und im Crypto-Service, und für #8 im Auth-Service).
            serviceTokenVault = envOrDev("SERVICE_TOKEN_VAULT", "dev-service-token-vault"),
            // Optional: CORS_ALLOWED_ORIGINS (kommagetrennt), CORS_ALLOW_NULL_ORIGIN (nur lokal true). localhost geht immer.
            cors = CorsConfig.fromEnv(),
        )
    }
}
