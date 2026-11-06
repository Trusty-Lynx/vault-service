package de.trustylynx.plugins

import de.trustylynx.models.ITEM_ID_HEADER
import de.trustylynx.models.VAULT_TOKEN_HEADER
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.cors.routing.CORS

// the website (MPA and SPA) is always allowed, same as in the auth-service, so the server needs no CORS config
private const val FRONTEND_ORIGIN = "https://trustylynx.nexvent.de"
private val LOCAL_ORIGIN = Regex("""^http://(localhost|127\.0\.0\.1):\d+$""")
private val ORIGIN = Regex("""^https?://[a-z0-9.-]+(:\d+)?$""")

data class CorsConfig(
    val allowedOrigins: Set<String> = emptySet(),
    val allowNullOrigin: Boolean = false,
) {
    companion object {
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
    install(CORS) {
        allowOrigins { origin ->
            LOCAL_ORIGIN.matches(origin) ||
                origin == FRONTEND_ORIGIN ||
                origin in config.allowedOrigins ||
                // `Origin: null` also comes from sandboxed iframes and some redirects, so from any website.
                // Local development only, never together with allowCredentials or cookies
                (config.allowNullOrigin && origin == "null")
        }
        // Ktor only allows GET, POST and HEAD by default. Without these the browser fails at the preflight
        // for PUT /items and DELETE /items (curl and Bruno don't notice)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(VAULT_TOKEN_HEADER)
        allowHeader(ITEM_ID_HEADER)
        allowHeader(HttpHeaders.XRequestId)
        exposeHeader(HttpHeaders.XRequestId)
    }
}
