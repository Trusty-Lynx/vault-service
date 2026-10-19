package de.trustylynx

import de.trustylynx.clients.HttpKeyServiceClient
import de.trustylynx.common.SERVICE_TOKEN_HEADER
import de.trustylynx.common.ServiceJson
import de.trustylynx.common.UpstreamException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandler
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.content.TextContent
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class HttpKeyServiceClientTest {

    @Test
    fun `pepperHmac schickt purpose vault und liefert h aus der Doku`() = runBlocking<Unit> {
        val client = clientRespondingWith { request ->
            assertEquals(HttpMethod.Post, request.method)
            assertEquals("http://key-service/internal/pepper-hmac", request.url.toString())
            assertEquals(SERVICE_TOKEN, request.headers[SERVICE_TOKEN_HEADER])

            val body = Json.parseToJsonElement((request.body as TextContent).text).jsonObject
            assertEquals("vault", body.getValue("purpose").jsonPrimitive.content)
            assertEquals("u42", body.getValue("userId").jsonPrimitive.content)
            assertEquals(UNLOCK_KEY_BASE64, body.getValue("key").jsonPrimitive.content)

            respondJson("""{"h":"$H_VAULT_BASE64"}""")
        }

        assertContentEquals(H_VAULT, client.pepperHmac("u42", UNLOCK_KEY))
    }

    @Test
    fun `Fehlerstatus vom Key-Service wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { respondJson("""{"error":"forbidden"}""", HttpStatusCode.Forbidden) }

        assertFailsWith<UpstreamException> { client.pepperHmac("u42", UNLOCK_KEY) }
    }

    @Test
    fun `h mit falscher Laenge wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { respondJson("""{"h":"AAAA"}""") }

        assertFailsWith<UpstreamException> { client.pepperHmac("u42", UNLOCK_KEY) }
    }

    @Test
    fun `kaputter Body wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { respondJson("""{"nope":1}""") }

        assertFailsWith<UpstreamException> { client.pepperHmac("u42", UNLOCK_KEY) }
    }

    @Test
    fun `Key-Service nicht erreichbar wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { throw java.net.ConnectException("Connection refused") }

        assertFailsWith<UpstreamException> { client.pepperHmac("u42", UNLOCK_KEY) }
    }

    private fun clientRespondingWith(handler: MockRequestHandler): HttpKeyServiceClient {
        // Gleiche Einstellungen wie createServiceHttpClient, nur mit MockEngine statt CIO.
        val http = HttpClient(MockEngine(handler)) {
            expectSuccess = false
            install(ContentNegotiation) { json(ServiceJson) }
        }
        return HttpKeyServiceClient(http, "http://key-service/", SERVICE_TOKEN)
    }

    private fun io.ktor.client.engine.mock.MockRequestHandleScope.respondJson(
        json: String,
        status: HttpStatusCode = HttpStatusCode.OK,
    ) = respond(json, status, headersOf(HttpHeaders.ContentType, "application/json"))

    private companion object {
        const val SERVICE_TOKEN = "test-service-token-vault"

        val UNLOCK_KEY = ByteArray(32) { it.toByte() }
        const val UNLOCK_KEY_BASE64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

        // h_vault aus V3 (Verschlüsselung.md), Base64 wie in pepper-hmac.md
        const val H_VAULT_BASE64 = "B7og0670VpQ5cFWd1/PLF9b8OnacX05g6E/Eyr1jAx0="
        val H_VAULT = "07ba20d3aef456943970559dd7f3cb17d6fc3a769c5f4e60e84fc4cabd63031d"
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
