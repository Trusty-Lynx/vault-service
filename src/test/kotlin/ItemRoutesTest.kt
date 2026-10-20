package de.trustylynx

import de.trustylynx.clients.CryptoPart
import de.trustylynx.common.DEVICE_ID_HEADER
import de.trustylynx.common.ITEM_ID_HEADER
import de.trustylynx.common.SESSION_ID_HEADER
import de.trustylynx.common.USER_ID_HEADER
import de.trustylynx.common.VAULT_TOKEN_HEADER
import de.trustylynx.domain.ItemService
import de.trustylynx.domain.StoredItem
import de.trustylynx.domain.VaultService
import de.trustylynx.domain.VaultSession
import de.trustylynx.security.VaultToken
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.header
import io.ktor.client.request.put
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
import kotlinx.serialization.json.int
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
import kotlin.test.assertTrue

class ItemRoutesTest {

    private val vaults = FakeVaultRepository()
    private val itemRepository = FakeItemRepository()
    private val keyService = FakeKeyService()
    private val cryptoService = FakeCryptoService()
    private val clock = Clock.fixed(Instant.parse("2026-10-21T12:00:00Z"), ZoneOffset.UTC)
    private val token = VaultToken.generate()

    // ---------- PUT /items ----------

    @Test
    fun `neuer Eintrag mit rev 1 wird mit Schicht 2 gespeichert`() = itemTest {
        val response = putItem(rev = 1)

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(1, response.rev())

        val stored = itemRepository.items.getValue("u42" to ITEM_ID)
        assertEquals(1, stored.rev)
        assertContentEquals(FakeCryptoService.c2Of(HEAD), stored.headC2)
        assertContentEquals(FakeCryptoService.c2Of(SECRET), stored.secretC2)
        // Beide Teile einzeln, mit itemId, damit der Crypto-Service sie in die AAD nimmt.
        assertEquals(
            listOf<Triple<String, CryptoPart, String?>>(Triple("u42", CryptoPart.HEAD, ITEM_ID), Triple("u42", CryptoPart.SECRET, ITEM_ID)),
            cryptoService.calls,
        )
    }

    @Test
    fun `Aenderung mit aktueller rev + 1 ueberschreibt den Eintrag`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(1), byteArrayOf(1))

        val response = putItem(rev = 2)

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(2, response.rev())
        assertEquals(2, itemRepository.items.getValue("u42" to ITEM_ID).rev)
        assertContentEquals(FakeCryptoService.c2Of(SECRET), itemRepository.items.getValue("u42" to ITEM_ID).secretC2)
    }

    @Test
    fun `neuer Eintrag mit rev 2 ergibt 409 mit currentRev 0 ohne Crypto-Service`() = itemTest {
        val response = putItem(rev = 2)

        assertEquals(HttpStatusCode.Conflict, response.status)
        assertEquals("rev_conflict", response.json("error"))
        assertEquals(0, response.rev("currentRev"))
        assertTrue(cryptoService.calls.isEmpty())
        assertTrue(itemRepository.items.isEmpty())
    }

    @Test
    fun `veraltete rev ergibt 409 mit aktueller currentRev und ueberschreibt nichts`() = itemTest {
        val existing = StoredItem(ITEM_ID, 3, byteArrayOf(7), byteArrayOf(7))
        itemRepository.items["u42" to ITEM_ID] = existing

        val response = putItem(rev = 3)

        assertEquals(HttpStatusCode.Conflict, response.status)
        assertEquals(3, response.rev("currentRev"))
        assertTrue(itemRepository.items.getValue("u42" to ITEM_ID) === existing)
    }

    @Test
    fun `Wettlauf zweier Geraete ergibt 409 mit der rev des Gewinners`() = itemTest {
        // Vorab-Prüfung sagt "frei", aber beim Speichern war ein anderes Gerät mit rev 1 schneller.
        itemRepository.loseRaceWithRev = 1

        val response = putItem(rev = 1)

        assertEquals(HttpStatusCode.Conflict, response.status)
        assertEquals(1, response.rev("currentRev"))
    }

    @Test
    fun `ohne Tresor-Token ergibt 401 vault_locked, noch vor jeder anderen Pruefung`() = itemTest {
        val response = client.put("/items") {
            callerHeaders()
            // absichtlich auch ohne X-Item-Id und mit kaputtem Body
            contentType(ContentType.Application.Json)
            setBody("{")
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("vault_locked"))
    }

    @Test
    fun `abgelaufener Tresor-Token ergibt 401 vault_locked`() = itemTest {
        vaults.sessions.clear()
        vaults.sessions += session(expiresAt = clock.instant())

        assertEquals(HttpStatusCode.Unauthorized, putItem(rev = 1).status)
        assertTrue(itemRepository.items.isEmpty())
    }

    @Test
    fun `gueltiger Aufruf verlaengert den Tresor-Token`() = itemTest {
        putItem(rev = 1)

        assertEquals(clock.instant().plus(Duration.ofMinutes(15)), vaults.sessions.single().expiresAt)
    }

    @Test
    fun `fehlende oder ungueltige X-Item-Id ergibt 400`() = itemTest {
        assertEquals(HttpStatusCode.BadRequest, putItem(rev = 1, itemId = null).status)
        assertEquals(HttpStatusCode.BadRequest, putItem(rev = 1, itemId = "a|b").status)
        assertTrue(itemRepository.items.isEmpty())
    }

    @Test
    fun `ungueltige Inhalte ergeben 400`() = itemTest {
        val notC1 = byteArrayOf(0x02, 0x01) + ByteArray(60)
        val wrongPadding = byteArrayOf(0x01, 0x01) + ByteArray(48 + 28) // Block 48 ist keine Zweierpotenz

        assertEquals(HttpStatusCode.BadRequest, putItem(rev = 0).status)
        assertEquals(HttpStatusCode.BadRequest, putItem(rev = 1, head = notC1).status)
        assertEquals(HttpStatusCode.BadRequest, putItem(rev = 1, secret = wrongPadding).status)
        assertEquals(HttpStatusCode.BadRequest, putItem(rev = 1, rawHead = "kein base64!").status)
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `Crypto-Service nicht erreichbar ergibt 502 und speichert nichts`() = itemTest {
        cryptoService.fail = true

        assertEquals(HttpStatusCode.BadGateway, putItem(rev = 1).status)
        assertTrue(itemRepository.items.isEmpty())
    }

    // ---------- Hilfen ----------

    private fun itemTest(block: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        environment { config = MapApplicationConfig() }
        vaults.sessions += session()
        application {
            configureApp(
                VaultService(vaults, keyService, cryptoService, clock),
                ItemService(itemRepository, cryptoService),
            )
        }
        block()
    }

    private fun session(expiresAt: Instant = clock.instant().plus(Duration.ofMinutes(10))) =
        VaultSession(VaultToken.hash(token), "u42", "dev-mac-01", "s-1", expiresAt)

    private fun HttpRequestBuilder.callerHeaders() {
        header(USER_ID_HEADER, "u42")
        header(DEVICE_ID_HEADER, "dev-mac-01")
        header(SESSION_ID_HEADER, "s-1")
    }

    private suspend fun ApplicationTestBuilder.putItem(
        rev: Int,
        itemId: String? = ITEM_ID,
        head: ByteArray = HEAD,
        secret: ByteArray = SECRET,
        rawHead: String = b64(head),
    ): HttpResponse = client.put("/items") {
        callerHeaders()
        header(VAULT_TOKEN_HEADER, token)
        if (itemId != null) header(ITEM_ID_HEADER, itemId)
        contentType(ContentType.Application.Json)
        setBody("""{"rev":$rev,"head":"$rawHead","secret":"${b64(secret)}"}""")
    }

    private suspend fun HttpResponse.json(field: String): String =
        Json.parseToJsonElement(bodyAsText()).jsonObject.getValue(field).jsonPrimitive.content

    private suspend fun HttpResponse.rev(field: String = "rev"): Int =
        Json.parseToJsonElement(bodyAsText()).jsonObject.getValue(field).jsonPrimitive.int

    private companion object {
        const val ITEM_ID = "3f2a9c1e-7b4d-4e2a-9c1e-0a1b2c3d4e5f"

        // Kopf: 128 Byte Padding-Block + 30 = 158 Byte, Geheimnis: 32 + 30 = 62 Byte (wie in der Doku)
        val HEAD = byteArrayOf(0x01, 0x01) + ByteArray(156) { 5 }
        val SECRET = byteArrayOf(0x01, 0x01) + ByteArray(60) { 6 }

        fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    }
}
