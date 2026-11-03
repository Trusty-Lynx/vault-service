package de.trustylynx.security

import de.trustylynx.clients.AuthServiceClient
import de.trustylynx.clients.VerifiedSession
import de.trustylynx.models.DEVICE_ID_HEADER
import de.trustylynx.models.NO_DEVICE_ID
import de.trustylynx.models.UpstreamException
import de.trustylynx.plugins.configureSerialization
import de.trustylynx.plugins.configureStatusPages
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

// tests the verifier on its own, with a route that only returns the verified caller
class LoginTokenVerifierTest {

    private val auth = FakeAuthService()

    @Test
    fun `gueltiger Token liefert Caller aus der Antwort des Auth-Service`() = verifierTest {
        val response = getMe { bearer(LOGIN_TOKEN); header(DEVICE_ID_HEADER, "dev-mac-01") }

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("u42|dev-mac-01|s-1", response.bodyAsText())
        assertEquals(LOGIN_TOKEN, auth.calledWith)
    }

    @Test
    fun `X-User-Id und X-Session-Id aus der Anfrage werden ignoriert`() = verifierTest {
        val response = getMe {
            bearer(LOGIN_TOKEN)
            header(DEVICE_ID_HEADER, "dev-mac-01")
            // the old placeholder headers from before #8 must not have any effect
            header("X-User-Id", "fremder-nutzer")
            header("X-Session-Id", "fremde-session")
        }

        assertEquals("u42|dev-mac-01|s-1", response.bodyAsText())
    }

    @Test
    fun `ohne X-Device-Id nimmt vorerst den Platzhalter`() = verifierTest {
        val response = getMe { bearer(LOGIN_TOKEN) }

        assertEquals("u42|$NO_DEVICE_ID|s-1", response.bodyAsText())
        assertEquals(LOGIN_TOKEN, auth.calledWith)
    }

    @Test
    fun `ohne Authorization ergibt 401 ohne Auth-Service`() = verifierTest {
        assertEquals(HttpStatusCode.Unauthorized, getMe { header(DEVICE_ID_HEADER, "dev-mac-01") }.status)
        assertNull(auth.calledWith)
    }

    @Test
    fun `falsches Schema oder kaputter Token ergibt 401 ohne Auth-Service`() = verifierTest {
        for (value in listOf("Basic abc", "Bearer ", "Bearer a b", "Bearer " + "x".repeat(513))) {
            assertEquals(HttpStatusCode.Unauthorized, getMe { header(HttpHeaders.Authorization, value) }.status, value)
        }
        assertNull(auth.calledWith)
    }

    @Test
    fun `ungueltige X-Device-Id ergibt 401 ohne Auth-Service`() = verifierTest {
        val response = getMe { bearer(LOGIN_TOKEN); header(DEVICE_ID_HEADER, "kaputt|id") }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertNull(auth.calledWith)
    }

    @Test
    fun `vom Auth-Service abgelehnter Token ergibt 401`() = verifierTest {
        auth.session = null

        val response = getMe { bearer(LOGIN_TOKEN); header(DEVICE_ID_HEADER, "dev-mac-01") }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(true, response.bodyAsText().contains("unauthorized"))
    }

    @Test
    fun `Auth-Service nicht erreichbar ergibt 502`() = verifierTest {
        auth.fail = true

        assertEquals(HttpStatusCode.BadGateway, getMe { bearer(LOGIN_TOKEN) }.status)
    }

    private fun verifierTest(block: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        environment { config = MapApplicationConfig() }
        val verifier = LoginTokenVerifier(auth)
        application {
            configureSerialization()
            configureStatusPages()
            routing {
                get("/me") {
                    val caller = verifier.verify(call)
                    call.respondText("${caller.userId}|${caller.deviceId}|${caller.sessionId}")
                }
            }
        }
        block()
    }

    private suspend fun ApplicationTestBuilder.getMe(headers: HttpRequestBuilder.() -> Unit): HttpResponse =
        client.get("/me", headers)

    private fun HttpRequestBuilder.bearer(token: String) = header(HttpHeaders.Authorization, "Bearer $token")

    private class FakeAuthService : AuthServiceClient {
        var fail = false
        var session: VerifiedSession? = session()
        var calledWith: String? = null

        override suspend fun verifySession(token: String): VerifiedSession? {
            calledWith = token
            if (fail) throw UpstreamException("auth-service down")
            return session
        }
    }

    private companion object {
        const val LOGIN_TOKEN = "Zt7wP2kQ9xL4mN8vB1cR6yH3sJ0fD5gA2eU7iO4nK1M="

        fun session() = VerifiedSession(
            userId = "u42",
            sessionId = "s-1",
            expiresAt = Instant.parse("2026-10-20T12:00:00Z"),
        )
    }
}
