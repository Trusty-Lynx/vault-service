package de.trustylynx

import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServiceClient
import de.trustylynx.clients.KeyServiceClient
import de.trustylynx.common.AlreadyExists
import de.trustylynx.common.DEVICE_ID_HEADER
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
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
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

    @Test
    fun `POST vault legt Tresor an und liefert Tresor-Token`() = vaultTest {
        val response = postVault(VALID_BODY)

        assertEquals(HttpStatusCode.Created, response.status)
        val token = Json.parseToJsonElement(response.bodyAsText()).jsonObject.getValue("vaultToken").jsonPrimitive.content

        val vault = assertNotNull(repository.vault)
        assertEquals("u42", vault.userId)
        assertContentEquals(SALT_VAULT, vault.saltVault)
        assertEquals(KdfParams.DEFAULT, vault.kdf)
        assertEquals(VerifierHasher.SALT_LENGTH, vault.saltSVault.size)
        // vault_verifier = Argon2id(h vom Key-Service, salt_s_vault)
        assertContentEquals(VerifierHasher.hash(FakeKeyService.H, vault.saltSVault), vault.vaultVerifier)
        // gespeichert wird nur, was der Crypto-Service zurückgibt
        assertContentEquals(FakeCryptoService.c2Of(WDEK), vault.wdekC2)

        assertEquals("u42", keyService.calledWith?.first)
        assertContentEquals(UNLOCK_KEY, keyService.calledWith?.second)
        assertEquals(Triple("u42", CryptoPart.DEK, null), cryptoService.calledWith)

        val session = assertNotNull(repository.session)
        assertContentEquals(VaultToken.hash(token), session.tokenHash)
        assertEquals("dev-mac-01", session.deviceId)
        assertEquals("s-1", session.sessionId)
        assertEquals(clock.instant().plus(Duration.ofMinutes(15)), session.expiresAt)
    }

    @Test
    fun `POST vault zweimal ergibt 409 ohne Key- und Crypto-Service`() = vaultTest {
        repository.existing = true

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

    private fun vaultTest(block: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        // Leere Config, damit nicht application.yaml geladen wird und module() mit echter DB startet.
        environment { config = MapApplicationConfig() }
        application { configureApp(VaultService(repository, keyService, cryptoService, clock)) }
        block()
    }

    private suspend fun ApplicationTestBuilder.postVault(body: String): HttpResponse = client.post("/vault") {
        header(USER_ID_HEADER, "u42")
        header(DEVICE_ID_HEADER, "dev-mac-01")
        header(SESSION_ID_HEADER, "s-1")
        contentType(ContentType.Application.Json)
        setBody(body)
    }

    private class FakeVaultRepository : VaultRepository {
        var existing = false
        var failWithConflict = false
        var vault: Vault? = null
        var session: VaultSession? = null

        override suspend fun exists(userId: String) = existing

        override suspend fun create(vault: Vault, session: VaultSession) {
            if (failWithConflict) throw AlreadyExists()
            this.vault = vault
            this.session = session
        }
    }

    private class FakeKeyService : KeyServiceClient {
        var fail = false
        var calledWith: Pair<String, ByteArray>? = null

        override suspend fun pepperHmac(userId: String, unlockKey: ByteArray): ByteArray {
            calledWith = userId to unlockKey.copyOf()
            if (fail) throw UpstreamException("key-service down")
            return H.copyOf()
        }

        companion object {
            val H = ByteArray(32) { 7 }
        }
    }

    private class FakeCryptoService : CryptoServiceClient {
        var fail = false
        var calledWith: Triple<String, CryptoPart, String?>? = null

        override suspend fun encrypt(userId: String, part: CryptoPart, c1: ByteArray, itemId: String?): ByteArray {
            calledWith = Triple(userId, part, itemId)
            if (fail) throw UpstreamException("crypto-service down")
            return c2Of(c1)
        }

        companion object {
            // Kein echtes AES, nur erkennbar: TLX2-Header + c1 + 28 Byte Füllung = c1 + 36 Byte
            fun c2Of(c1: ByteArray): ByteArray =
                byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, 0x01, 0x00, 0x01) + c1 + ByteArray(28)
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
