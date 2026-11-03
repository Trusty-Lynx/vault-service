package de.trustylynx.plugins

import de.trustylynx.models.DEVICE_ID_HEADER
import de.trustylynx.models.ITEM_ID_HEADER
import de.trustylynx.models.VAULT_TOKEN_HEADER
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.plugins.cors.routing.CORS

private val LOCAL_ORIGIN = Regex("""^http://(localhost|127\.0\.0\.1):\d+$""")
private val ORIGIN = Regex("""^https?://[a-z0-9.-]+(:\d+)?$""")

data class CorsConfig(
    val allowedOrigins: Set<String> = emptySet(),
    val allowNullOrigin: Boolean = false,
    // true when CORS_ALLOWED_ORIGINS isn't set, then every origin may call us. That's ok because we don't use
    // cookies, a foreign website doesn't know the login or vault token headers.
    // TODO: remove once the website domain is fixed and CORS_ALLOWED_ORIGINS is set on the server
    val allowAnyOrigin: Boolean = false,
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
    if (config.allowAnyOrigin) {
        log.warn("CORS_ALLOWED_ORIGINS is not set: every origin may call the vault-service (temporary)")
    }
    install(CORS) {
        // answers with "Access-Control-Allow-Origin: *", only ok because we never use allowCredentials
        if (config.allowAnyOrigin) anyHost()
        allowOrigins { origin ->
            LOCAL_ORIGIN.matches(origin) ||
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
        // dashboard.js still sends the old placeholders from before #8. We ignore them, but without these lines
        // the browser would already block the preflight.
        // TODO: remove once dashboard.js stops sending them
        allowHeader("X-User-Id")
        allowHeader("X-Session-Id")
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
