package de.trustylynx.clients

import de.trustylynx.models.UpstreamException
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.callid.CallId
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.appendPathSegments
import io.ktor.http.isSuccess
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import java.io.IOException
import java.nio.channels.UnresolvedAddressException

// tolerant to new fields in the other services' answers
val ServiceJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
}

fun createServiceHttpClient(): HttpClient = HttpClient(CIO) {
    // bodyOrThrow checks the status itself, so every failure ends up as UpstreamException (502)
    expectSuccess = false
    install(ContentNegotiation) { json(ServiceJson) }
    install(HttpTimeout) {
        connectTimeoutMillis = 2_000
        requestTimeoutMillis = 10_000
    }
    // passes the X-Request-Id of the current request on to the other service
    install(CallId) { addToHeader(HttpHeaders.XRequestId) }
}

fun serviceUrl(baseUrl: String, vararg segments: String): Url =
    URLBuilder(baseUrl.trimEnd('/')).appendPathSegments(*segments).build()

// Network errors become UpstreamException, so the client gets a 502 and not a 500. Timeouts are IOExceptions too,
// an unknown hostname is not, so that one is caught separately
suspend inline fun <T> callUpstream(what: String, block: () -> T): T = try {
    block()
} catch (e: IOException) {
    throw UpstreamException("$what unreachable: ${e.message}", e)
} catch (e: UnresolvedAddressException) {
    throw UpstreamException("$what unreachable: hostname cannot be resolved (check the service URL)", e)
}

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
