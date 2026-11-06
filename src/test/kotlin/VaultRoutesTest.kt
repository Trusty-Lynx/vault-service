package de.trustylynx

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.CryptoServices
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.models.AlreadyExists
import de.trustylynx.models.Caller
import de.trustylynx.models.IntegrityError
import de.trustylynx.models.KdfParams
import de.trustylynx.models.UpstreamException
import de.trustylynx.models.VAULT_TOKEN_HEADER
import de.trustylynx.models.Vault
import de.trustylynx.models.VaultLocked
import de.trustylynx.models.VaultSession
import de.trustylynx.repositories.VaultRepository
import de.trustylynx.security.LoginTokenVerifier
import de.trustylynx.security.VaultToken
import de.trustylynx.security.VerifierHasher
import de.trustylynx.services.ItemService
import de.trustylynx.services.VaultService
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class VaultRoutesTest {

    private val repository = FakeVaultRepository()
    private val keyService = FakeKeyService()
    private val cryptoService = FakeCryptoService()
    private val auth = FakeAuthService()
    private val clock = Clock.fixed(Instant.parse("2026-10-19T12:00:00Z"), ZoneOffset.UTC)

    @Test
    fun `POST vault legt Tresor an und liefert Tresor-Token`() = vaultTest {
        val response = postVault(VALID_BODY)

        assertEquals(HttpStatusCode.Created, response.status)
        val token = response.json().getValue("vaultToken").jsonPrimitive.content

        val vault = assertNotNull(repository.vault)
        assertEquals("u42", vault.userId)
        assertContentEquals(SALT_VAULT, vault.saltVault)
        assertEquals(KdfParams.DEFAULT, vault.kdf)
        assertEquals(VerifierHasher.SALT_LENGTH, vault.saltSVault.size)
        // vault_verifier = Argon2id(h from the key service, salt_s_vault)
        assertContentEquals(VerifierHasher.hash(FakeKeyService.h(UNLOCK_KEY), vault.saltSVault), vault.vaultVerifier)
        // only what the crypto service returns gets stored
        assertContentEquals(FakeCryptoService.c2Of(WDEK), vault.wdekC2)

        assertEquals("u42", keyService.calledWith?.first)
        assertContentEquals(UNLOCK_KEY, keyService.calledWith?.second)
        assertEquals(Triple("u42", CryptoPart.DEK, null), cryptoService.calledWith)

        val session = repository.sessions.single()
        assertContentEquals(VaultToken.hash(token), session.tokenHash)
        assertEquals("s-1", session.sessionId)
        assertEquals(clock.instant().plus(Duration.ofMinutes(15)), session.expiresAt)
    }

    @Test
    fun `POST vault zweimal ergibt 409 ohne Key- und Crypto-Service`() = vaultTest {
        repository.vault = storedVault()

        val response = postVault(VALID_BODY)

        assertEquals(HttpStatusCode.Conflict, response.status)
        assertTrue(response.bodyAsText().contains("already_exists"))
        assertNull(keyService.calledWith)
        assertNull(cryptoService.calledWith)
    }

    @Test
    fun `POST vault mit Wettlauf im Repository ergibt 409`() = vaultTest {
        repository.failWithConflict = true

        assertEquals(HttpStatusCode.Conflict, postVault(VALID_BODY).status)
    }

    @Test
    fun `POST vault mit falschem wdek ergibt 400`() = vaultTest {
        val body = VALID_BODY.replace(b64(WDEK), b64(ByteArray(62)))

        assertEquals(HttpStatusCode.BadRequest, postVault(body).status)
        assertNull(repository.vault)
    }

    @Test
    fun `POST vault ohne Caller-Header ergibt 401`() = vaultTest {
        val response = client.post("/vault") {
            contentType(ContentType.Application.Json)
            setBody(VALID_BODY)
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `POST vault ignoriert eine alte X-Device-Id`() = vaultTest {
        val response = client.post("/vault") {
            header(HttpHeaders.Authorization, "Bearer $LOGIN_TOKEN")
            header("X-Device-Id", "kaputt|id")
            contentType(ContentType.Application.Json)
            setBody(VALID_BODY)
        }

        assertEquals(HttpStatusCode.Created, response.status)
    }

    @Test
    fun `Key-Service nicht erreichbar ergibt 502 und speichert nichts`() = vaultTest {
        keyService.fail = true

        assertEquals(HttpStatusCode.BadGateway, postVault(VALID_BODY).status)
        assertNull(repository.vault)
    }

    @Test
    fun `Crypto-Service nicht erreichbar ergibt 502 und speichert nichts`() = vaultTest {
        cryptoService.fail = true

        assertEquals(HttpStatusCode.BadGateway, postVault(VALID_BODY).status)
        assertNull(repository.vault)
    }

    @Test
    fun `params liefert Salt und KDF ohne Seiteneffekt`() = vaultTest {
        repository.vault = storedVault()

        val response = getParams()

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            Json.parseToJsonElement(
                """{"salt":"${b64(SALT_VAULT)}","kdf":{"alg":"argon2id","m":65536,"t":3,"p":1,"len":32}}""",
            ),
            response.json(),
        )
        // no vault token, no other services
        assertTrue(repository.sessions.isEmpty())
        assertNull(keyService.calledWith)
        assertNull(cryptoService.calledWith)
    }

    @Test
    fun `params ohne Tresor ergibt 404`() = vaultTest {
        val response = getParams()

        assertEquals(HttpStatusCode.NotFound, response.status)
        assertTrue(response.bodyAsText().contains("not_found"))
    }

    @Test
    fun `params liefert nicht den Tresor eines anderen Nutzers`() = vaultTest {
        repository.vault = storedVault()

        val response = client.get("/vault/params") {
            header(HttpHeaders.Authorization, "Bearer $LOGIN_TOKEN_U43")
        }

        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    @Test
    fun `params ohne Caller-Header ergibt 401`() = vaultTest {
        repository.vault = storedVault()

        assertEquals(HttpStatusCode.Unauthorized, client.get("/vault/params").status)
    }

    @Test
    fun `unlock mit richtigem unlockKey liefert wDEK und neuen Tresor-Token`() = vaultTest {
        repository.vault = storedVault()

        val response = postUnlock(UNLOCK_KEY)

        assertEquals(HttpStatusCode.OK, response.status)
        val json = response.json()
        assertEquals(900, json.getValue("expiresIn").jsonPrimitive.long)
        // wDEK = wdek_c2 without layer 2, exactly as the client sent it with POST /vault
        assertEquals(b64(WDEK), json.getValue("wdek").jsonPrimitive.content)
        assertEquals(Triple("u42", CryptoPart.DEK, null), cryptoService.calledWith)

        val token = json.getValue("vaultToken").jsonPrimitive.content
        val session = repository.sessions.single()
        assertContentEquals(VaultToken.hash(token), session.tokenHash)
        assertEquals("u42", session.userId)
        assertEquals("s-1", session.sessionId)
        assertEquals(clock.instant().plus(Duration.ofMinutes(15)), session.expiresAt)
    }

    @Test
    fun `unlock mit falschem unlockKey ergibt 401 ohne wDEK und Token`() = vaultTest {
        repository.vault = storedVault()

        val response = postUnlock(ByteArray(32) { 9 })

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("unauthorized"))
        assertNull(cryptoService.calledWith)
        assertTrue(repository.sessions.isEmpty())
    }

    @Test
    fun `unlock ohne Tresor ergibt 404 ohne Key-Service`() = vaultTest {
        val response = postUnlock(UNLOCK_KEY)

        assertEquals(HttpStatusCode.NotFound, response.status)
        assertNull(keyService.calledWith)
    }

    @Test
    fun `unlock mit unlockKey falscher Laenge ergibt 400`() = vaultTest {
        repository.vault = storedVault()

        assertEquals(HttpStatusCode.BadRequest, postUnlock(ByteArray(31)).status)
        assertNull(keyService.calledWith)
    }

    @Test
    fun `unlock ohne Caller-Header ergibt 401`() = vaultTest {
        repository.vault = storedVault()

        val response = client.post("/vault/unlock") {
            contentType(ContentType.Application.Json)
            setBody("""{"unlockKey":"${b64(UNLOCK_KEY)}"}""")
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `unlock mit manipuliertem wdek_c2 ergibt 500 integrity_error ohne Token`() = vaultTest {
        repository.vault = storedVault()
        cryptoService.integrityError = true

        val response = postUnlock(UNLOCK_KEY)

        assertEquals(HttpStatusCode.InternalServerError, response.status)
        assertTrue(response.bodyAsText().contains("integrity_error"))
        assertTrue(repository.sessions.isEmpty())
    }

    @Test
    fun `unlock mit nicht erreichbarem Crypto-Service ergibt 502 ohne Token`() = vaultTest {
        repository.vault = storedVault()
        cryptoService.fail = true

        assertEquals(HttpStatusCode.BadGateway, postUnlock(UNLOCK_KEY).status)
        assertTrue(repository.sessions.isEmpty())
    }

    @Test
    fun `unlock raeumt abgelaufene Tresor-Tokens des Nutzers weg`() = vaultTest {
        repository.vault = storedVault()
        repository.sessions += session(VaultToken.generate(), expiresAt = clock.instant().minusSeconds(1))
        repository.sessions += session(VaultToken.generate(), userId = "u43", expiresAt = clock.instant().minusSeconds(1))

        assertEquals(HttpStatusCode.OK, postUnlock(UNLOCK_KEY).status)

        // left: the new token of u42 and the expired one of u43 (unlock doesn't touch other users)
        assertEquals(listOf("u42", "u43"), repository.sessions.map { it.userId }.sorted())
        assertTrue(repository.sessions.single { it.userId == "u42" }.expiresAt.isAfter(clock.instant()))
    }

    @Test
    fun `gueltiger Tresor-Token wird akzeptiert und um 15 min verlaengert`() = runBlocking<Unit> {
        val token = VaultToken.generate()
        repository.sessions += session(token, expiresAt = clock.instant().plusSeconds(60))

        service().requireUnlocked(CALLER, token)

        assertEquals(clock.instant().plus(Duration.ofMinutes(15)), repository.sessions.single().expiresAt)
    }

    @Test
    fun `Tresor-Token fehlt, ist kaputt oder unbekannt ergibt vault_locked`() = runBlocking<Unit> {
        repository.sessions += session(VaultToken.generate())

        for (token in listOf(null, "", "zu-kurz", "x".repeat(43) + "!", VaultToken.generate())) {
            assertFailsWith<VaultLocked>("token=$token") { service().requireUnlocked(CALLER, token) }
        }
    }

    @Test
    fun `abgelaufener Tresor-Token ergibt vault_locked und wird nicht verlaengert`() = runBlocking<Unit> {
        val token = VaultToken.generate()
        repository.sessions += session(token, expiresAt = clock.instant())

        assertFailsWith<VaultLocked> { service().requireUnlocked(CALLER, token) }
        assertEquals(clock.instant(), repository.sessions.single().expiresAt)
    }

    @Test
    fun `Tresor-Token gilt nur fuer denselben Nutzer und dieselbe Login-Session`() = runBlocking<Unit> {
        val token = VaultToken.generate()
        repository.sessions += session(token)

        for (other in listOf(
            Caller("u43", "s-1"),
            // logged out and in again, new sessionId, so the old vault token is dead
            Caller("u42", "s-2"),
        )) {
            assertFailsWith<VaultLocked>("caller=${other.userId}/${other.sessionId}") {
                service().requireUnlocked(other, token)
            }
        }
    }

    @Test
    fun `lock widerruft den Tresor-Token, danach ist er ungueltig`() = vaultTest {
        val token = VaultToken.generate()
        repository.sessions += session(token)

        val response = postLock(token)

        assertEquals(HttpStatusCode.NoContent, response.status)
        assertTrue(repository.sessions.isEmpty())
        assertFailsWith<VaultLocked> { service().requireUnlocked(CALLER, token) }
    }

    @Test
    fun `lock zweimal ergibt beim zweiten Mal vault_locked`() = vaultTest {
        val token = VaultToken.generate()
        repository.sessions += session(token)

        assertEquals(HttpStatusCode.NoContent, postLock(token).status)
        val second = postLock(token)

        assertEquals(HttpStatusCode.Unauthorized, second.status)
        assertTrue(second.bodyAsText().contains("vault_locked"))
    }

    @Test
    fun `lock ohne Tresor-Token ergibt vault_locked`() = vaultTest {
        val response = postLock(null)

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("vault_locked"))
    }

    @Test
    fun `lock betrifft nur diesen Tresor-Token`() = vaultTest {
        val mine = VaultToken.generate()
        val otherTab = VaultToken.generate()
        repository.sessions += session(mine)
        repository.sessions += session(otherTab)

        assertEquals(HttpStatusCode.NoContent, postLock(mine).status)

        assertContentEquals(VaultToken.hash(otherTab), repository.sessions.single().tokenHash)
    }

    @Test
    fun `lock mit dem Token einer anderen Login-Session ergibt vault_locked und loescht nichts`() = vaultTest {
        val otherSession = VaultToken.generate()
        repository.sessions += session(otherSession, sessionId = "s-2")

        assertEquals(HttpStatusCode.Unauthorized, postLock(otherSession).status)
        assertEquals(1, repository.sessions.size)
    }

    @Test
    fun `die alten Platzhalter-Header X-User-Id und X-Session-Id allein reichen nicht mehr`() = vaultTest {
        repository.vault = storedVault()

        val response = client.get("/vault/params") {
            header("X-User-Id", "u42")
            header("X-Session-Id", "s-1")
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals(0, auth.calls)
    }

    @Test
    fun `unbekannter oder abgelaufener Login-Token ergibt 401 unauthorized`() = vaultTest {
        repository.vault = storedVault()

        val response = client.get("/vault/params") { header(HttpHeaders.Authorization, "Bearer unbekannter-token") }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("unauthorized"))
    }

    @Test
    fun `nach dem Logout ist auch ein noch gueltiger Tresor-Token wertlos`() = vaultTest {
        val token = VaultToken.generate()
        repository.sessions += session(token)
        auth.sessions.remove(LOGIN_TOKEN) // login session ended

        val response = postLock(token)

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("unauthorized"))
        assertEquals(1, repository.sessions.size)
    }

    @Test
    fun `Auth-Service nicht erreichbar ergibt 502`() = vaultTest {
        auth.fail = true

        assertEquals(HttpStatusCode.BadGateway, getParams().status)
    }

    private fun service() = VaultService(repository, keyService, cryptoService, clock)

    private fun session(
        token: String,
        userId: String = "u42",
        sessionId: String = "s-1",
        expiresAt: Instant = clock.instant().plus(Duration.ofMinutes(10)),
    ) = VaultSession(VaultToken.hash(token), userId, sessionId, expiresAt)

    private suspend fun ApplicationTestBuilder.postLock(token: String?): HttpResponse = client.post("/vault/lock") {
        callerHeaders()
        if (token != null) header(VAULT_TOKEN_HEADER, token)
    }

    private fun vaultTest(block: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        // empty config, otherwise application.yaml gets loaded and module() starts with a real DB
        environment { config = MapApplicationConfig() }
        application { configureApp(VaultService(repository, keyService, cryptoService, clock), ItemService(FakeItemRepository(), CryptoServices(aes = cryptoService, chacha = cryptoService)), LoginTokenVerifier(auth)) }
        block()
    }

    private suspend fun ApplicationTestBuilder.postVault(body: String): HttpResponse = client.post("/vault") {
        callerHeaders()
        contentType(ContentType.Application.Json)
        setBody(body)
    }

    private suspend fun ApplicationTestBuilder.getParams(): HttpResponse = client.get("/vault/params") {
        callerHeaders()
    }

    private suspend fun ApplicationTestBuilder.postUnlock(unlockKey: ByteArray): HttpResponse = client.post("/vault/unlock") {
        callerHeaders()
        contentType(ContentType.Application.Json)
        setBody("""{"unlockKey":"${b64(unlockKey)}"}""")
    }

    private fun io.ktor.client.request.HttpRequestBuilder.callerHeaders() {
        header(HttpHeaders.Authorization, "Bearer $LOGIN_TOKEN")
    }

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject

    // a vault like POST /vault would have created it with UNLOCK_KEY and WDEK
    private fun storedVault(): Vault {
        val saltSVault = ByteArray(16) { 4 }
        return Vault(
            userId = "u42",
            saltVault = SALT_VAULT,
            kdf = KdfParams.DEFAULT,
            saltSVault = saltSVault,
            vaultVerifier = VerifierHasher.hash(FakeKeyService.h(UNLOCK_KEY), saltSVault),
            wdekC2 = FakeCryptoService.c2Of(WDEK),
        )
    }

    private companion object {
        // same caller as in callerHeaders()
        val CALLER = Caller(userId = "u42", sessionId = "s-1")
        val SALT_VAULT = ByteArray(16) { 1 }
        val UNLOCK_KEY = ByteArray(32) { 2 }
        val WDEK = byteArrayOf(0x01, 0x01) + ByteArray(60) { 3 }

        fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

        val VALID_BODY = """
            {
              "salt": "${b64(SALT_VAULT)}",
              "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 1, "len": 32 },
              "unlockKey": "${b64(UNLOCK_KEY)}",
              "wdek": "${b64(WDEK)}"
            }
        """.trimIndent()
    }
}
