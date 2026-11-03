package de.trustylynx

import de.trustylynx.clients.CryptoServices
import de.trustylynx.models.SERVICE_TOKEN_HEADER
import de.trustylynx.models.VaultSession
import de.trustylynx.security.LoginTokenVerifier
import de.trustylynx.security.VaultToken
import de.trustylynx.services.ItemService
import de.trustylynx.services.VaultService
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// the breach service calls this, it only checks for leaks while the vault is unlocked
class InternalRoutesTest {

    private val repository = FakeVaultRepository()
    private val clock = Clock.fixed(Instant.parse("2026-10-28T12:00:00Z"), ZoneOffset.UTC)
    private val vaultToken = VaultToken.generate()

    @Test
    fun `entsperrter Tresor ergibt 204 und verlaengert die Leerlaufzeit`() = internalTest {
        repository.sessions += session(expiresAt = clock.instant().plusSeconds(10))

        val response = postUnlocked(body())

        assertEquals(HttpStatusCode.NoContent, response.status)
        assertEquals(clock.instant().plus(VaultToken.IDLE_TIMEOUT), repository.sessions.single().expiresAt)
    }

    @Test
    fun `ohne Tresor-Session ergibt 401 vault_locked`() = internalTest {
        val response = postUnlocked(body())

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue("vault_locked" in response.bodyAsText())
    }

    @Test
    fun `abgelaufener, fremder oder kaputter Tresor-Token ergibt 401 vault_locked`() = internalTest {
        repository.sessions += session(expiresAt = clock.instant().minusSeconds(1))
        assertEquals(HttpStatusCode.Unauthorized, postUnlocked(body()).status)

        repository.sessions.clear()
        repository.sessions += session()
        assertEquals(HttpStatusCode.Unauthorized, postUnlocked(body(userId = "u43")).status)
        assertEquals(HttpStatusCode.Unauthorized, postUnlocked(body(sessionId = "s-2")).status)
        assertEquals(HttpStatusCode.Unauthorized, postUnlocked(body(deviceId = "anderes-geraet")).status)
        assertEquals(HttpStatusCode.Unauthorized, postUnlocked(body(token = "kaputt")).status)
    }

    @Test
    fun `ohne oder mit falschem Service-Token ergibt 403`() = internalTest {
        repository.sessions += session()

        assertEquals(HttpStatusCode.Forbidden, postUnlocked(body(), serviceToken = null).status)
        assertEquals(HttpStatusCode.Forbidden, postUnlocked(body(), serviceToken = "falsch").status)
        assertEquals(HttpStatusCode.Forbidden, postUnlocked("{kaputt", serviceToken = null).status)
    }

    @Test
    fun `ungueltige IDs ergeben 400`() = internalTest {
        assertEquals(HttpStatusCode.BadRequest, postUnlocked(body(userId = "u42|x")).status)
    }

    @Test
    fun `ohne Breach-Token gibt es die Route nicht`() = testApplication {
        environment { config = MapApplicationConfig() }
        application { configureApp(service(), ItemService(FakeItemRepository(), CryptoServices(aes = FakeCryptoService(), chacha = FakeCryptoService())), LoginTokenVerifier(FakeAuthService())) }

        assertEquals(HttpStatusCode.NotFound, client.post(PATH).status)
    }

    private fun service() = VaultService(repository, FakeKeyService(), FakeCryptoService(), clock)

    private fun session(expiresAt: Instant = clock.instant().plus(Duration.ofMinutes(10))) =
        VaultSession(VaultToken.hash(vaultToken), "u42", "dev-mac-01", "s-1", expiresAt)

    private fun body(
        userId: String = "u42",
        sessionId: String = "s-1",
        deviceId: String = "dev-mac-01",
        token: String = vaultToken,
    ) = """{"userId":"$userId","sessionId":"$sessionId","deviceId":"$deviceId","vaultToken":"$token"}"""

    private fun internalTest(block: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        // empty config, otherwise application.yaml gets loaded and module() starts with a real DB
        environment { config = MapApplicationConfig() }
        application {
            configureApp(
                service(),
                ItemService(FakeItemRepository(), CryptoServices(aes = FakeCryptoService(), chacha = FakeCryptoService())),
                LoginTokenVerifier(FakeAuthService()),
                breachToken = BREACH_TOKEN,
            )
        }
        block()
    }

    private suspend fun ApplicationTestBuilder.postUnlocked(body: String, serviceToken: String? = BREACH_TOKEN): HttpResponse =
        client.post(PATH) {
            if (serviceToken != null) header(SERVICE_TOKEN_HEADER, serviceToken)
            contentType(ContentType.Application.Json)
            setBody(body)
        }

    private companion object {
        const val PATH = "/internal/vault/unlocked"
        const val BREACH_TOKEN = "test-service-token-breach"
    }
}
