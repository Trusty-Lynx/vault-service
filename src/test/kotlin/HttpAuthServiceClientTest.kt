package de.trustylynx

import de.trustylynx.clients.HttpAuthServiceClient
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
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class HttpAuthServiceClientTest {

    @Test
    fun `verifySession schickt Token und deviceId und liefert die Session aus der Doku`() = runBlocking<Unit> {
        val client = clientRespondingWith { request ->
            assertEquals(HttpMethod.Post, request.method)
            assertEquals("http://auth-service/internal/sessions/verify", request.url.toString())
            assertEquals(SERVICE_TOKEN, request.headers[SERVICE_TOKEN_HEADER])

            val body = Json.parseToJsonElement((request.body as TextContent).text).jsonObject
            assertEquals(LOGIN_TOKEN, body.getValue("token").jsonPrimitive.content)
            assertEquals("dev-mac-01", body.getValue("deviceId").jsonPrimitive.content)

            respondJson(VERIFY_RESPONSE)
        }

        val session = assertNotNull(client.verifySession(LOGIN_TOKEN, "dev-mac-01"))
        assertEquals("3a0b4d3e-5c1f-4e2a-9b7d-1f2e3c4d5a6b", session.userId)
        assertEquals("9c1f7a2b-3d4e-4f5a-8b6c-7d8e9f0a1b2c", session.sessionId)
        assertEquals("dev-mac-01", session.deviceId)
        assertEquals(Instant.ofEpochSecond(1791500000), session.expiresAt)
    }

    @Test
    fun `ohne deviceId wird das Feld nicht mitgeschickt`() = runBlocking<Unit> {
        // Für den Auth-Service nach dem Umbau ohne Guard: Body nur {token}, Antwort ohne deviceId.
        val client = clientRespondingWith { request ->
            val body = Json.parseToJsonElement((request.body as TextContent).text).jsonObject
            assertFalse("deviceId" in body)
            respondJson("""{"userId":"u42","sessionId":"s-1","expiresAt":1791500000}""")
        }

        val session = assertNotNull(client.verifySession(LOGIN_TOKEN, null))
        assertEquals("u42", session.userId)
        assertNull(session.deviceId)
    }

    @Test
    fun `401 vom Auth-Service ergibt null`() = runBlocking<Unit> {
        val client = clientRespondingWith { respondJson("""{"error":"unauthorized"}""", HttpStatusCode.Unauthorized) }

        assertNull(client.verifySession(LOGIN_TOKEN, "dev-mac-01"))
    }

    @Test
    fun `403 (Vault nicht freigeschaltet) wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { respondJson("""{"error":"forbidden"}""", HttpStatusCode.Forbidden) }

        assertFailsWith<UpstreamException> { client.verifySession(LOGIN_TOKEN, "dev-mac-01") }
    }

    @Test
    fun `kaputter Body wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { respondJson("""{"nope":1}""") }

        assertFailsWith<UpstreamException> { client.verifySession(LOGIN_TOKEN, "dev-mac-01") }
    }

    @Test
    fun `ungueltige userId in der Antwort wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith {
            respondJson("""{"userId":"u42|x","sessionId":"s-1","expiresAt":1791500000}""")
        }

        assertFailsWith<UpstreamException> { client.verifySession(LOGIN_TOKEN, "dev-mac-01") }
    }

    @Test
    fun `Auth-Service nicht erreichbar wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { throw java.net.ConnectException("Connection refused") }

        assertFailsWith<UpstreamException> { client.verifySession(LOGIN_TOKEN, "dev-mac-01") }
    }

    private fun clientRespondingWith(handler: MockRequestHandler): HttpAuthServiceClient {
        // Gleiche Einstellungen wie createServiceHttpClient, nur mit MockEngine statt CIO.
        val http = HttpClient(MockEngine(handler)) {
            expectSuccess = false
            install(ContentNegotiation) { json(ServiceJson) }
        }
        return HttpAuthServiceClient(http, "http://auth-service/", SERVICE_TOKEN)
    }

    private fun io.ktor.client.engine.mock.MockRequestHandleScope.respondJson(
        json: String,
        status: HttpStatusCode = HttpStatusCode.OK,
    ) = respond(json, status, headersOf(HttpHeaders.ContentType, "application/json"))

    private companion object {
        const val SERVICE_TOKEN = "test-service-token-vault"

        // Beispiele aus auth-service/API.md
        const val LOGIN_TOKEN = "Zt7wP2kQ9xL4mN8vB1cR6yH3sJ0fD5gA2eU7iO4nK1M="
        const val VERIFY_RESPONSE = """{
            "userId": "3a0b4d3e-5c1f-4e2a-9b7d-1f2e3c4d5a6b",
            "deviceId": "dev-mac-01",
            "sessionId": "9c1f7a2b-3d4e-4f5a-8b6c-7d8e9f0a1b2c",
            "expiresAt": 1791500000
        }"""
    }
}
