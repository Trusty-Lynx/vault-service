package de.trustylynx

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.common.Caller
import de.trustylynx.common.CorsConfig
import de.trustylynx.domain.Vault
import de.trustylynx.domain.ItemService
import de.trustylynx.domain.VaultService
import de.trustylynx.domain.VaultSession
import de.trustylynx.persistence.VaultRepository
import io.ktor.client.request.header
import io.ktor.client.request.options
import io.ktor.client.request.post
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val LIVE_SERVER = "http://127.0.0.1:5500"
private const val APP_ORIGIN = "https://app.nexvent.de"

/** Nach dem CorsTest im auth-service. POST /vault ohne Caller-Header gibt 401, das reicht für CORS. */
class CorsTest {

    @Test
    fun `eine lokale Origin darf aufrufen, auch Fehlerantworten tragen den CORS-Header`() = corsTest {
        val response = postVaultFrom(LIVE_SERVER)

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(LIVE_SERVER, response.allowOrigin())
    }

    @Test
    fun `Preflight von lokaler Origin erlaubt JSON und unsere Header`() = corsTest {
        val response = preflight("http://localhost:3000", "content-type,x-user-id,x-session-id,x-device-id,x-vault-token")

        assertTrue(response.status.value in 200..299, "status ${response.status}")
        assertEquals("http://localhost:3000", response.allowOrigin())
        val allowed = assertNotNull(response.headers[HttpHeaders.AccessControlAllowHeaders]).lowercase()
        for (h in listOf("content-type", "x-user-id", "x-session-id", "x-device-id", "x-vault-token")) {
            assertTrue(h in allowed, "$h fehlt in $allowed")
        }
    }

    @Test
    fun `Preflight mit unbekanntem Header wird abgelehnt`() = corsTest {
        val response = preflight("http://localhost:3000", "content-type,x-evil")

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertNull(response.allowOrigin())
    }

    @Test
    fun `eine konfigurierte Origin darf aufrufen`() = corsTest(CorsConfig(allowedOrigins = setOf(APP_ORIGIN))) {
        assertEquals(APP_ORIGIN, postVaultFrom(APP_ORIGIN).allowOrigin())
    }

    @Test
    fun `die null-Origin ist nur erlaubt, wenn eingeschaltet`() {
        corsTest(CorsConfig(allowNullOrigin = true)) {
            assertEquals("null", postVaultFrom("null").allowOrigin())
        }
        corsTest {
            val response = postVaultFrom("null")
            assertEquals(HttpStatusCode.Forbidden, response.status)
            assertNull(response.allowOrigin())
        }
    }

    @Test
    fun `ohne CORS_ALLOWED_ORIGINS darf vorerst jede Origin aufrufen`() = corsTest(CorsConfig(allowAnyOrigin = true)) {
        val response = postVaultFrom("https://website.example")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("*", response.allowOrigin())

        val preflight = preflight("https://website.example", "content-type,x-user-id,x-session-id")
        assertTrue(preflight.status.value in 200..299, "status ${preflight.status}")
    }

    @Test
    fun `eine fremde Origin wird abgelehnt`() = corsTest {
        val response = postVaultFrom("https://evil.example")

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertNull(response.allowOrigin())
    }

    @Test
    fun `ein Host, der nur mit localhost anfaengt, wird abgelehnt`() = corsTest {
        val response = postVaultFrom("http://localhost.evil.example:5500")

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertNull(response.allowOrigin())
    }

    @Test
    fun `Anfragen ohne Origin (Bruno, curl, andere Services) sind nicht betroffen`() = corsTest {
        val response = client.post("/vault")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.headers.names().none { it.startsWith("Access-Control-", ignoreCase = true) })
    }

    @Test
    fun `erlaubte Origins werden getrimmt und kleingeschrieben`() {
        assertEquals(
            setOf(APP_ORIGIN, "http://localhost:8080"),
            CorsConfig.parseAllowedOrigins(" https://App.nexvent.de , ,http://localhost:8080,"),
        )
        assertEquals(emptySet(), CorsConfig.parseAllowedOrigins(""))
    }

    @Test
    fun `ungueltige Origins werden abgelehnt`() {
        for (origin in listOf("*", "app.nexvent.de", "https://app.nexvent.de/", "https://app.nexvent.de/api", "null")) {
            assertFailsWith<IllegalArgumentException>(origin) { CorsConfig.parseAllowedOrigins(origin) }
        }
    }

    @Test
    fun `das null-Flag akzeptiert nur true oder false`() {
        assertTrue(CorsConfig.parseFlag("CORS_ALLOW_NULL_ORIGIN", "true"))
        assertFalse(CorsConfig.parseFlag("CORS_ALLOW_NULL_ORIGIN", "false"))
        assertFailsWith<IllegalStateException> { CorsConfig.parseFlag("CORS_ALLOW_NULL_ORIGIN", "yes") }
    }

    private fun corsTest(cors: CorsConfig = CorsConfig(), block: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        environment { config = MapApplicationConfig() }
        application { configureApp(VaultService(UnusedRepository, UnusedKeyService, UnusedCryptoService), ItemService(FakeItemRepository(), UnusedCryptoService), cors) }
        block()
    }

    private suspend fun ApplicationTestBuilder.postVaultFrom(origin: String): HttpResponse = client.post("/vault") {
        header(HttpHeaders.Origin, origin)
    }

    private suspend fun ApplicationTestBuilder.preflight(origin: String, requestHeaders: String): HttpResponse =
        client.options("/vault") {
            header(HttpHeaders.Origin, origin)
            header(HttpHeaders.AccessControlRequestMethod, "POST")
            header(HttpHeaders.AccessControlRequestHeaders, requestHeaders)
        }

    private fun HttpResponse.allowOrigin(): String? = headers[HttpHeaders.AccessControlAllowOrigin]

    // Die Requests scheitern schon an caller() (401), der Service wird nie erreicht.
    private object UnusedRepository : VaultRepository {
        override suspend fun exists(userId: String) = error("unused")
        override suspend fun find(userId: String) = error("unused")
        override suspend fun create(vault: Vault, session: VaultSession) = error("unused")
        override suspend fun createSession(session: VaultSession) = error("unused")
        override suspend fun touchSession(tokenHash: ByteArray, caller: Caller, now: Instant, newExpiresAt: Instant) = error("unused")
        override suspend fun deleteSession(tokenHash: ByteArray, caller: Caller, now: Instant) = error("unused")
        override suspend fun deleteExpiredSessions(userId: String, now: Instant) = error("unused")
    }

    private object UnusedKeyService : KeyServiceClient {
        override suspend fun pepperHmac(userId: String, unlockKey: ByteArray) = error("unused")
    }

    private object UnusedCryptoService : CryptoServiceClient {
        override suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String?) = error("unused")
        override suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String?) = error("unused")
    }
}
