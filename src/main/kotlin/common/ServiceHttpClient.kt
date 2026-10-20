package de.trustylynx.common

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.statement.HttpResponse
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.appendPathSegments
import io.ktor.http.isSuccess
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.CancellationException
import java.io.IOException
import java.nio.channels.UnresolvedAddressException

/** Header, an dem andere Services den Vault-Service erkennen. */
const val SERVICE_TOKEN_HEADER = "X-Service-Token"

/** HTTP-Client für Aufrufe an andere Services. Muss beim Stoppen der Anwendung geschlossen werden. */
fun createServiceHttpClient(): HttpClient = HttpClient(CIO) {
    // Statuscodes prüft bodyOrThrow selbst, damit jeder Fehler als UpstreamException (502) endet.
    expectSuccess = false
    install(ContentNegotiation) { json(ServiceJson) }
    install(HttpTimeout) {
        connectTimeoutMillis = 2_000
        requestTimeoutMillis = 10_000
    }
}

fun serviceUrl(baseUrl: String, vararg segments: String): Url =
    URLBuilder(baseUrl.trimEnd('/')).appendPathSegments(*segments).build()

/**
 * Führt den Aufruf an einen anderen Service aus. Netzwerkfehler (Verbindung abgelehnt, Timeout) → [UpstreamException],
 * damit daraus 502 wird und nicht 500. Timeouts von HttpTimeout sind ebenfalls IOExceptions.
 * Hostname nicht auflösbar ist dagegen KEINE IOException (UnresolvedAddressException), deshalb extra.
 */
suspend inline fun <T> callUpstream(what: String, block: () -> T): T = try {
    block()
} catch (e: IOException) {
    throw UpstreamException("$what unreachable: ${e.message}", e)
} catch (e: UnresolvedAddressException) {
    throw UpstreamException("$what unreachable: hostname cannot be resolved (check the service URL)", e)
}

/** Liest den Body als [T]. Fehlerstatus oder unlesbarer Body → [UpstreamException]. */
suspend inline fun <reified T> HttpResponse.bodyOrThrow(what: String): T {
    if (!status.isSuccess()) throw UpstreamException("$what answered ${status.value}")
    return try {
        body<T>()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        throw UpstreamException("$what: unreadable response body", e)
    }
}
