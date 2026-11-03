package de.trustylynx

import de.trustylynx.plugins.CorsConfig
import de.trustylynx.repositories.DbConfig

class AppConfig(
    val db: DbConfig,
    val keyServiceUrl: String,
    val cryptoServiceUrl: String,
    val cryptoAesServiceUrl: String,
    val authServiceUrl: String,
    val serviceTokenVault: String,
    val serviceTokenAes: String,
    val serviceTokenGateway: String,
    val serviceTokenBreach: String,
    val cors: CorsConfig,
) {
    companion object {
        fun fromEnv() = AppConfig(
            db = DbConfig(
                url = envOrDev("DB_URL", "jdbc:postgresql://localhost:5435/vault"),
                user = envOrDev("DB_USER", "dev"),
                password = envOrDev("DB_PASSWORD", "dev"),
            ),
            keyServiceUrl = envOrDev("KEY_SERVICE_URL", "http://localhost:7492"),
            // ChaCha service: does the wDEK and every item with alg = chacha
            cryptoServiceUrl = envOrDev("CRYPTO_SERVICE_URL", "http://localhost:7494"),
            // AES service, only for items with alg = aes. Optional so the vault still starts without it,
            // if it's down only AES items fail with 502 crypto_unavailable
            cryptoAesServiceUrl = env("CRYPTO_AES_SERVICE_URL", "http://crypto-service-aes256gcm:8080"),
            authServiceUrl = env("AUTH_SERVICE_URL", "http://auth-service:8080"),
            // key and ChaCha service know this one as VAULT_SERVICE_TOKEN
            serviceTokenVault = envOrDev("SERVICE_TOKEN_VAULT", "dev-service-token-vault"),
            // same value as AES_SERVICE_TOKEN in the AES service
            serviceTokenAes = envOrDev("SERVICE_TOKEN_AES", "dev-service-token-aes"),
            // the auth service only knows the gateway token for /internal/sessions/verify, so we use that one
            serviceTokenGateway = envOrDev("SERVICE_TOKEN_GATEWAY", "dev-service-token-gateway"),
            // the breach service uses this one for POST /internal/vault/unlocked
            serviceTokenBreach = envOrDev("SERVICE_TOKEN_BREACH", "dev-service-token-breach"),
            cors = corsFromEnv(),
        )
    }
}

private val isDev: Boolean =
    System.getProperty("io.ktor.development")?.toBoolean() == true

// a blank value counts as not set
private fun env(name: String, default: String): String {
    val value = System.getenv(name)
    return if (value.isNullOrBlank()) default else value
}

// required in prod, the default only applies in dev mode
private fun envOrDev(name: String, devDefault: String): String {
    val value = System.getenv(name)
    if (!value.isNullOrBlank()) return value
    if (isDev) return devDefault
    error("Missing required environment variable $name")
}

private fun corsFromEnv(): CorsConfig {
    val origins = env("CORS_ALLOWED_ORIGINS", "")
    return CorsConfig(
        allowedOrigins = CorsConfig.parseAllowedOrigins(origins),
        allowNullOrigin = CorsConfig.parseFlag("CORS_ALLOW_NULL_ORIGIN", env("CORS_ALLOW_NULL_ORIGIN", "false")),
        allowAnyOrigin = origins.isBlank(),
    )
}
