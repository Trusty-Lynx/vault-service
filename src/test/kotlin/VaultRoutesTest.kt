package de.trustylynx

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.common.AlreadyExists
import de.trustylynx.common.DEVICE_ID_HEADER
import de.trustylynx.common.IntegrityError
import de.trustylynx.common.SESSION_ID_HEADER
import de.trustylynx.common.USER_ID_HEADER
import de.trustylynx.common.UpstreamException
import de.trustylynx.domain.KdfParams
import de.trustylynx.domain.Vault
import de.trustylynx.domain.VaultService
import de.trustylynx.domain.VaultSession
import de.trustylynx.persistence.VaultRepository
import de.trustylynx.security.VaultToken
import de.trustylynx.security.VerifierHasher
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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class VaultRoutesTest {

    private val repository = FakeVaultRepository()
    private val keyService = FakeKeyService()
    private val cryptoService = FakeCryptoService()
    private val clock = Clock.fixed(Instant.parse("2026-10-19T12:00:00Z"), ZoneOffset.UTC)

    // ---------- POST /vault ----------

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
        // vault_verifier = Argon2id(h vom Key-Service, salt_s_vault)
        assertContentEquals(VerifierHasher.hash(FakeKeyService.h(UNLOCK_KEY), vault.saltSVault), vault.vaultVerifier)
        // gespeichert wird nur, was der Crypto-Service zurückgibt
        assertContentEquals(FakeCryptoService.c2Of(WDEK), vault.wdekC2)

        assertEquals("u42", keyService.calledWith?.first)
        assertContentEquals(UNLOCK_KEY, keyService.calledWith?.second)
        assertEquals(Triple("u42", CryptoPart.DEK, null), cryptoService.calledWith)

        val session = repository.sessions.single()
        assertContentEquals(VaultToken.hash(token), session.tokenHash)
        assertEquals("dev-mac-01", session.deviceId)
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

    // ---------- POST /vault/unlock ----------

    @Test
    fun `unlock mit richtigem unlockKey liefert wDEK und neuen Tresor-Token`() = vaultTest {
        repository.vault = storedVault()

        val response = postUnlock(UNLOCK_KEY)

        assertEquals(HttpStatusCode.OK, response.status)
        val json = response.json()
        assertEquals(900, json.getValue("expiresIn").jsonPrimitive.long)
        // wDEK = wdek_c2 ohne Schicht 2, genau so, wie der Client ihn bei POST /vault geschickt hat
        assertEquals(b64(WDEK), json.getValue("wdek").jsonPrimitive.content)
        assertEquals(Triple("u42", CryptoPart.DEK, null), cryptoService.calledWith)

        val token = json.getValue("vaultToken").jsonPrimitive.content
        val session = repository.sessions.single()
        assertContentEquals(VaultToken.hash(token), session.tokenHash)
        assertEquals("u42", session.userId)
        assertEquals("dev-mac-01", session.deviceId)
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

    // ---------- Hilfen ----------

    private fun vaultTest(block: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        // Leere Config, damit nicht application.yaml geladen wird und module() mit echter DB startet.
        environment { config = MapApplicationConfig() }
        application { configureApp(VaultService(repository, keyService, cryptoService, clock)) }
        block()
    }

    private suspend fun ApplicationTestBuilder.postVault(body: String): HttpResponse = client.post("/vault") {
        callerHeaders()
        contentType(ContentType.Application.Json)
        setBody(body)
    }

    private suspend fun ApplicationTestBuilder.postUnlock(unlockKey: ByteArray): HttpResponse = client.post("/vault/unlock") {
        callerHeaders()
        contentType(ContentType.Application.Json)
        setBody("""{"unlockKey":"${b64(unlockKey)}"}""")
    }

    private fun io.ktor.client.request.HttpRequestBuilder.callerHeaders() {
        header(USER_ID_HEADER, "u42")
        header(DEVICE_ID_HEADER, "dev-mac-01")
        header(SESSION_ID_HEADER, "s-1")
    }

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject

    /** Ein Tresor, wie POST /vault ihn mit UNLOCK_KEY und WDEK angelegt hätte. */
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

    private class FakeVaultRepository : VaultRepository {
        var failWithConflict = false
        var vault: Vault? = null
        val sessions = mutableListOf<VaultSession>()

        override suspend fun exists(userId: String) = vault?.userId == userId

        override suspend fun find(userId: String) = vault?.takeIf { it.userId == userId }

        override suspend fun create(vault: Vault, session: VaultSession) {
            if (failWithConflict) throw AlreadyExists()
            this.vault = vault
            sessions += session
        }

        override suspend fun createSession(session: VaultSession) {
            sessions += session
        }
    }

    private class FakeKeyService : KeyServiceClient {
        var fail = false
        var calledWith: Pair<String, ByteArray>? = null

        override suspend fun pepperHmac(userId: String, unlockKey: ByteArray): ByteArray {
            calledWith = userId to unlockKey.copyOf()
            if (fail) throw UpstreamException("key-service down")
            return h(unlockKey)
        }

        companion object {
            // Kein echtes HMAC, aber wie HMAC: anderer unlockKey → anderes h.
            fun h(unlockKey: ByteArray): ByteArray = ByteArray(32) { (unlockKey[it] + 1).toByte() }
        }
    }

    private class FakeCryptoService : CryptoServiceClient {
        var fail = false
        var integrityError = false
        var calledWith: Triple<String, CryptoPart, String?>? = null

        override suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String?): ByteArray {
            calledWith = Triple(userId, part, itemId)
            if (fail) throw UpstreamException("crypto-service down")
            return c2Of(c1)
        }

        override suspend fun decrypt(userId: String, part: CryptoPart, c2: ByteArray, itemId: String?): ByteArray {
            calledWith = Triple(userId, part, itemId)
            if (fail) throw UpstreamException("crypto-service down")
            if (integrityError) throw IntegrityError()
            return c2.copyOfRange(HEADER.size, c2.size - FILLER)
        }

        companion object {
            private val HEADER = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, 0x02, 0x00, 0x01)
            private const val FILLER = 28

            // Kein echtes ChaCha20, nur erkennbar: TLX2-Header + c1 + 28 Byte Füllung = c1 + 36 Byte
            fun c2Of(c1: ByteArray): ByteArray = HEADER + c1 + ByteArray(FILLER)
        }
    }

    private companion object {
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
