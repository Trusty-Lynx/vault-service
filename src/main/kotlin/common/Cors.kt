package de.trustylynx.common

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.plugins.cors.routing.CORS

// Übernommen aus dem auth-service (common/Cors.kt), damit sich beide Services gleich verhalten.

private val LOCAL_ORIGIN = Regex("""^http://(localhost|127\.0\.0\.1):\d+$""")
private val ORIGIN = Regex("""^https?://[a-z0-9.-]+(:\d+)?$""")

data class CorsConfig(
    val allowedOrigins: Set<String> = emptySet(),
    val allowNullOrigin: Boolean = false,
    /**
     * VORÜBERGEHEND: true, wenn CORS_ALLOWED_ORIGINS nicht gesetzt ist. Dann darf jede Origin aufrufen,
     * damit auf dem Server erstmal nichts eingetragen werden muss. Vertretbar, weil wir keine Cookies nutzen:
     * Eine fremde Website kennt die Header (Login-/Tresor-Token) nicht.
     * TODO: Entfernen, sobald die Domain der Website feststeht und auf dem Server CORS_ALLOWED_ORIGINS gesetzt ist.
     */
    val allowAnyOrigin: Boolean = false,
) {
    companion object {
        fun fromEnv(): CorsConfig {
            val origins = env("CORS_ALLOWED_ORIGINS", "")
            return CorsConfig(
                allowedOrigins = parseAllowedOrigins(origins),
                allowNullOrigin = parseFlag("CORS_ALLOW_NULL_ORIGIN", env("CORS_ALLOW_NULL_ORIGIN", "false")),
                allowAnyOrigin = origins.isBlank(),
            )
        }

        fun parseAllowedOrigins(value: String): Set<String> =
            value.split(',')
                .map { it.trim().lowercase() }
                .filter { it.isNotEmpty() }
                .onEach {
                    require(ORIGIN.matches(it)) {
                        "CORS_ALLOWED_ORIGINS: invalid origin '$it', expected http(s)://host[:port]"
                    }
                }
                .toSet()

        fun parseFlag(name: String, value: String): Boolean =
            value.toBooleanStrictOrNull() ?: error("$name must be true or false")
    }
}

fun Application.configureCors(config: CorsConfig) {
    if (config.allowAnyOrigin) {
        log.warn("CORS_ALLOWED_ORIGINS is not set: every origin may call the vault-service (temporary)")
    }
    install(CORS) {
        // Antwortet mit "Access-Control-Allow-Origin: *". Geht nur, weil wir kein allowCredentials nutzen.
        if (config.allowAnyOrigin) anyHost()
        allowOrigins { origin ->
            LOCAL_ORIGIN.matches(origin) ||
                origin in config.allowedOrigins ||
                // `Origin: null` schicken nicht nur lokal geöffnete Dateien, sondern auch sandboxed iframes und
                // manche Redirects, also potenziell jede Website. Nur für die lokale Entwicklung, auf dem Server
                // bleibt CORS_ALLOW_NULL_ORIGIN false. Nie zusammen mit allowCredentials oder Cookies verwenden.
                (config.allowNullOrigin && origin == "null")
        }
        // Ktor erlaubt standardmäßig nur GET, POST und HEAD. PUT /items und DELETE /items brauchen das hier,
        // sonst scheitert der Browser schon am Preflight (Bruno/curl merken davon nichts).
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Authorization)
        // Platzhalter bis #8: Solange wir den Login-Token nicht selbst prüfen, schickt der Client diese Header mit.
        allowHeader(USER_ID_HEADER)
        allowHeader(SESSION_ID_HEADER)
        allowHeader(DEVICE_ID_HEADER)
        allowHeader(VAULT_TOKEN_HEADER)
        allowHeader(ITEM_ID_HEADER)
        allowHeader("X-Timestamp")
        allowHeader("X-Device-Sig")
        allowHeader(HttpHeaders.XRequestId)
        exposeHeader(HttpHeaders.XRequestId)
        exposeHeader(HttpHeaders.RetryAfter)
    }
}
