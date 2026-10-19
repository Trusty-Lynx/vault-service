package de.trustylynx

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.HttpCryptoServiceClient
import de.trustylynx.common.SERVICE_TOKEN_HEADER
import de.trustylynx.common.ServiceJson
import de.trustylynx.common.UpstreamException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.MockRequestHandler
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.content.TextContent
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class HttpCryptoServiceClientTest {

    @Test
    fun `encrypt schickt dek ohne itemId und liefert C2`() = runBlocking<Unit> {
        val c2 = TLX2_AES + WDEK + ByteArray(28)
        val client = clientRespondingWith { request ->
            assertEquals("http://crypto-1/internal/encrypt", request.url.toString())
            assertEquals(SERVICE_TOKEN, request.headers[SERVICE_TOKEN_HEADER])

            val body = Json.parseToJsonElement((request.body as TextContent).text).jsonObject
            assertEquals("u42", body.getValue("userId").jsonPrimitive.content)
            assertEquals("dek", body.getValue("part").jsonPrimitive.content)
            assertEquals(b64(WDEK), body.getValue("c1").jsonPrimitive.content)
            // explicitNulls = false: itemId darf bei dek gar nicht im JSON stehen
            assertTrue("itemId" !in body || body["itemId"] == JsonNull)

            respondJson("""{"c2":"${b64(c2)}"}""")
        }

        assertContentEquals(c2, client.encrypt("u42", CryptoPart.DEK, WDEK))
    }

    @Test
    fun `C2 mit falscher Laenge wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { respondJson("""{"c2":"${b64(TLX2_AES + WDEK)}"}""") }

        assertFailsWith<UpstreamException> { client.encrypt("u42", CryptoPart.DEK, WDEK) }
    }

    @Test
    fun `C2 ohne TLX2-AES-Header wird zu UpstreamException`() = runBlocking<Unit> {
        val chacha = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, 0x02, 0x00, 0x01) + WDEK + ByteArray(28)
        val client = clientRespondingWith { respondJson("""{"c2":"${b64(chacha)}"}""") }

        assertFailsWith<UpstreamException> { client.encrypt("u42", CryptoPart.DEK, WDEK) }
    }

    @Test
    fun `Fehlerstatus vom Crypto-Service wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { respondJson("""{"error":"forbidden"}""", HttpStatusCode.Forbidden) }

        assertFailsWith<UpstreamException> { client.encrypt("u42", CryptoPart.DEK, WDEK) }
    }

    @Test
    fun `Crypto-Service nicht erreichbar wird zu UpstreamException`() = runBlocking<Unit> {
        val client = clientRespondingWith { throw java.net.ConnectException("Connection refused") }

        assertFailsWith<UpstreamException> { client.encrypt("u42", CryptoPart.DEK, WDEK) }
    }

    private fun clientRespondingWith(handler: MockRequestHandler): HttpCryptoServiceClient {
        val http = HttpClient(MockEngine(handler)) {
            expectSuccess = false
            install(ContentNegotiation) { json(ServiceJson) }
        }
        return HttpCryptoServiceClient(http, "http://crypto-1", SERVICE_TOKEN)
    }

    private fun MockRequestHandleScope.respondJson(json: String, status: HttpStatusCode = HttpStatusCode.OK) =
        respond(json, status, headersOf(HttpHeaders.ContentType, "application/json"))

    private companion object {
        const val SERVICE_TOKEN = "test-service-token-vault"
        val TLX2_AES = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, 0x01, 0x00, 0x01)
        val WDEK = byteArrayOf(0x01, 0x01) + ByteArray(60) { 3 }

        fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    }
}
