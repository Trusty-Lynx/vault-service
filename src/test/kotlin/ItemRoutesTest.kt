package de.trustylynx

import de.trustylynx.clients.CryptoAlg
import de.trustylynx.clients.CryptoPart
import de.trustylynx.clients.CryptoServices
import de.trustylynx.models.DEVICE_ID_HEADER
import de.trustylynx.models.ITEM_ID_HEADER
import de.trustylynx.models.StoredItem
import de.trustylynx.models.VAULT_TOKEN_HEADER
import de.trustylynx.models.VaultSession
import de.trustylynx.security.LoginTokenVerifier
import de.trustylynx.security.VaultToken
import de.trustylynx.services.ItemService
import de.trustylynx.services.VaultService
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.put
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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
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
    private val aesService = FakeCryptoService(CryptoAlg.AES)
    private val clock = Clock.fixed(Instant.parse("2026-10-21T12:00:00Z"), ZoneOffset.UTC)
    private val token = VaultToken.generate()

    @Test
    fun `neuer Eintrag mit rev 1 wird mit Schicht 2 gespeichert`() = itemTest {
        val response = putItem(rev = 1)

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(1, response.rev())

        val stored = itemRepository.items.getValue("u42" to ITEM_ID)
        assertEquals(1, stored.rev)
        assertContentEquals(FakeCryptoService.c2Of(HEAD), stored.headC2)
        assertContentEquals(FakeCryptoService.c2Of(SECRET), stored.secretC2)
        // both parts separately and with itemId, so the crypto service puts it into the AAD
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
        // the early check says "free", but another device saved rev 1 first
        itemRepository.loseRaceWithRev = 1

        val response = putItem(rev = 1)

        assertEquals(HttpStatusCode.Conflict, response.status)
        assertEquals(1, response.rev("currentRev"))
    }

    @Test
    fun `ohne Tresor-Token ergibt 401 vault_locked, noch vor jeder anderen Pruefung`() = itemTest {
        val response = client.put("/items") {
            callerHeaders()
            // on purpose without X-Item-Id and with a broken body
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
        val wrongPadding = byteArrayOf(0x01, 0x01) + ByteArray(48 + 28) // a 48 byte block is not a power of two

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

    @Test
    fun `ohne alg wird mit ChaCha gespeichert, AES bleibt unberuehrt`() = itemTest {
        assertEquals(HttpStatusCode.OK, putItem(rev = 1).status)

        assertContentEquals(FakeCryptoService.c2Of(HEAD, CryptoAlg.CHACHA), itemRepository.items.getValue("u42" to ITEM_ID).headC2)
        assertEquals(2, cryptoService.calls.size)
        assertTrue(aesService.calls.isEmpty())
    }

    @Test
    fun `alg aes speichert beide Teile ueber Crypto-Service 1`() = itemTest {
        val response = putItem(rev = 1, alg = "aes")

        assertEquals(HttpStatusCode.OK, response.status)
        val stored = itemRepository.items.getValue("u42" to ITEM_ID)
        assertContentEquals(FakeCryptoService.c2Of(HEAD, CryptoAlg.AES), stored.headC2)
        assertContentEquals(FakeCryptoService.c2Of(SECRET, CryptoAlg.AES), stored.secretC2)
        assertEquals(2, aesService.calls.size)
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `Wechsel beim Bearbeiten verschluesselt mit dem anderen Service neu`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] =
            StoredItem(ITEM_ID, 1, FakeCryptoService.c2Of(HEAD, CryptoAlg.AES), FakeCryptoService.c2Of(SECRET, CryptoAlg.AES))

        assertEquals(HttpStatusCode.OK, putItem(rev = 2, alg = "chacha").status)

        assertContentEquals(FakeCryptoService.c2Of(SECRET, CryptoAlg.CHACHA), itemRepository.items.getValue("u42" to ITEM_ID).secretC2)
        assertTrue(aesService.calls.isEmpty())
    }

    @Test
    fun `unbekannter alg ergibt 400 ohne Crypto-Service`() = itemTest {
        assertEquals(HttpStatusCode.BadRequest, putItem(rev = 1, alg = "rot13").status)
        assertTrue(cryptoService.calls.isEmpty() && aesService.calls.isEmpty())
        assertTrue(itemRepository.items.isEmpty())
    }

    @Test
    fun `AES nicht erreichbar ergibt 502 crypto_unavailable mit reason aes, ChaCha geht weiter`() = itemTest {
        aesService.fail = true

        val failed = putItem(rev = 1, alg = "aes")
        assertEquals(HttpStatusCode.BadGateway, failed.status)
        assertEquals("crypto_unavailable", failed.json("error"))
        assertEquals("aes", failed.json("reason"))
        assertTrue(itemRepository.items.isEmpty())

        assertEquals(HttpStatusCode.OK, putItem(rev = 1, alg = "chacha").status)
    }

    @Test
    fun `GET items liefert alg pro Eintrag und entschluesselt beim richtigen Service`() = itemTest {
        itemRepository.items["u42" to "a"] = StoredItem("a", 1, FakeCryptoService.c2Of(HEAD, CryptoAlg.AES), byteArrayOf(9))
        itemRepository.items["u42" to "b"] = StoredItem("b", 1, FakeCryptoService.c2Of(HEAD, CryptoAlg.CHACHA), byteArrayOf(9))

        val response = getItems()

        assertEquals(HttpStatusCode.OK, response.status)
        val list = Json.parseToJsonElement(response.bodyAsText()).jsonObject.getValue("items").jsonArray.map { it.jsonObject }
        assertEquals(listOf("aes", "chacha"), list.map { it.getValue("alg").jsonPrimitive.content })
        assertEquals(listOf(b64(HEAD), b64(HEAD)), list.map { it.getValue("head").jsonPrimitive.content })
        assertEquals(listOf<Triple<String, CryptoPart, String?>>(Triple("u42", CryptoPart.HEAD, "a")), aesService.calls)
        assertEquals(listOf<Triple<String, CryptoPart, String?>>(Triple("u42", CryptoPart.HEAD, "b")), cryptoService.calls)
    }

    @Test
    fun `GET secret eines AES-Eintrags geht an Crypto-Service 1`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), FakeCryptoService.c2Of(SECRET, CryptoAlg.AES))

        val response = getSecret()

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(b64(SECRET), response.json("data"))
        assertEquals(1, aesService.calls.size)
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `GET secret mit nicht erreichbarem AES ergibt 502 crypto_unavailable`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), FakeCryptoService.c2Of(SECRET, CryptoAlg.AES))
        aesService.fail = true

        val response = getSecret()

        assertEquals(HttpStatusCode.BadGateway, response.status)
        assertEquals("aes", response.json("reason"))
    }

    @Test
    fun `gespeichertes C2 mit unbekanntem Algorithmus-Byte ergibt 500 integrity_error`() = itemTest {
        val unknown = byteArrayOf(0x54, 0x4c, 0x58, 0x32, 0x02, 0x07, 0x00, 0x01) + SECRET + ByteArray(28)
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), unknown)

        val response = getSecret()

        assertEquals(HttpStatusCode.InternalServerError, response.status)
        assertTrue(response.bodyAsText().contains("integrity_error"))
        assertTrue(cryptoService.calls.isEmpty() && aesService.calls.isEmpty())
    }

    @Test
    fun `neuer Tresor liefert leere Liste`() = itemTest {
        val response = getItems()

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("""{"items":[]}""", response.bodyAsText())
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `liefert nur die eigenen Koepfe als C1, ohne Passwoerter`() = itemTest {
        val headB = byteArrayOf(0x01, 0x01) + ByteArray(156) { 8 }
        itemRepository.items["u42" to "b"] = StoredItem("b", 2, FakeCryptoService.c2Of(headB), byteArrayOf(9))
        itemRepository.items["u42" to "a"] = StoredItem("a", 1, FakeCryptoService.c2Of(HEAD), byteArrayOf(9))
        itemRepository.items["u43" to "c"] = StoredItem("c", 1, FakeCryptoService.c2Of(HEAD), byteArrayOf(9))

        val response = getItems()

        assertEquals(HttpStatusCode.OK, response.status)
        val list = Json.parseToJsonElement(response.bodyAsText()).jsonObject.getValue("items").jsonArray.map { it.jsonObject }
        assertEquals(listOf("a", "b"), list.map { it.getValue("id").jsonPrimitive.content })
        assertEquals(listOf(1, 2), list.map { it.getValue("rev").jsonPrimitive.int })
        assertEquals(listOf(b64(HEAD), b64(headB)), list.map { it.getValue("head").jsonPrimitive.content })
        assertTrue(list.all { "secret" !in it })
        // only part h, each with itemId. Never s
        assertEquals(
            setOf<Triple<String, CryptoPart, String?>>(Triple("u42", CryptoPart.HEAD, "a"), Triple("u42", CryptoPart.HEAD, "b")),
            cryptoService.calls.toSet(),
        )
    }

    @Test
    fun `GET items ohne Tresor-Token ergibt 401 vault_locked`() = itemTest {
        itemRepository.items["u42" to "a"] = StoredItem("a", 1, FakeCryptoService.c2Of(HEAD), byteArrayOf(9))

        val response = client.get("/items") { callerHeaders() }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("vault_locked"))
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `manipulierter Kopf ergibt 500 integrity_error`() = itemTest {
        itemRepository.items["u42" to "a"] = StoredItem("a", 1, FakeCryptoService.c2Of(HEAD), byteArrayOf(9))
        cryptoService.integrityError = true

        val response = getItems()

        assertEquals(HttpStatusCode.InternalServerError, response.status)
        assertTrue(response.bodyAsText().contains("integrity_error"))
    }

    @Test
    fun `GET items mit nicht erreichbarem Crypto-Service ergibt 502`() = itemTest {
        itemRepository.items["u42" to "a"] = StoredItem("a", 1, FakeCryptoService.c2Of(HEAD), byteArrayOf(9))
        cryptoService.fail = true

        assertEquals(HttpStatusCode.BadGateway, getItems().status)
    }

    @Test
    fun `liefert das Geheimnis als C1 mit rev`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 4, byteArrayOf(9), FakeCryptoService.c2Of(SECRET))

        val response = getSecret()

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(b64(SECRET), response.json("data"))
        assertEquals(4, response.rev())
        assertEquals(listOf<Triple<String, CryptoPart, String?>>(Triple("u42", CryptoPart.SECRET, ITEM_ID)), cryptoService.calls)
    }

    @Test
    fun `unbekannter oder fremder Eintrag ergibt 404 ohne Crypto-Service`() = itemTest {
        itemRepository.items["u43" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), FakeCryptoService.c2Of(SECRET))

        val response = getSecret()

        assertEquals(HttpStatusCode.NotFound, response.status)
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `GET secret ohne Tresor-Token ergibt 401 vault_locked`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), FakeCryptoService.c2Of(SECRET))

        val response = client.get("/items/secret") {
            callerHeaders()
            header(ITEM_ID_HEADER, ITEM_ID)
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("vault_locked"))
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `GET secret ohne oder mit ungueltiger X-Item-Id ergibt 400`() = itemTest {
        assertEquals(HttpStatusCode.BadRequest, getSecret(itemId = null).status)
        assertEquals(HttpStatusCode.BadRequest, getSecret(itemId = "a|b").status)
    }

    @Test
    fun `manipuliertes Geheimnis ergibt 500 integrity_error`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), FakeCryptoService.c2Of(SECRET))
        cryptoService.integrityError = true

        val response = getSecret()

        assertEquals(HttpStatusCode.InternalServerError, response.status)
        assertTrue(response.bodyAsText().contains("integrity_error"))
    }

    @Test
    fun `Crypto-Service lehnt ab oder ist nicht erreichbar ergibt 502`() = itemTest {
        // also what it looks like while the ChaCha service still wants a guard ticket for part s (403 becomes 502)
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), FakeCryptoService.c2Of(SECRET))
        cryptoService.fail = true

        assertEquals(HttpStatusCode.BadGateway, getSecret().status)
    }

    @Test
    fun `loescht den Eintrag mit 204`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), byteArrayOf(9))
        itemRepository.items["u42" to "andere"] = StoredItem("andere", 1, byteArrayOf(9), byteArrayOf(9))

        val response = deleteItem()

        assertEquals(HttpStatusCode.NoContent, response.status)
        assertEquals(setOf("u42" to "andere"), itemRepository.items.keys)
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `zweites Loeschen ergibt 404`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), byteArrayOf(9))

        assertEquals(HttpStatusCode.NoContent, deleteItem().status)
        assertEquals(HttpStatusCode.NotFound, deleteItem().status)
    }

    @Test
    fun `Eintrag eines anderen Nutzers wird nicht geloescht, 404`() = itemTest {
        itemRepository.items["u43" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), byteArrayOf(9))

        assertEquals(HttpStatusCode.NotFound, deleteItem().status)
        assertTrue(("u43" to ITEM_ID) in itemRepository.items)
    }

    @Test
    fun `DELETE ohne Tresor-Token ergibt 401 vault_locked und loescht nichts`() = itemTest {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, byteArrayOf(9), byteArrayOf(9))

        val response = client.delete("/items") {
            callerHeaders()
            header(ITEM_ID_HEADER, ITEM_ID)
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("vault_locked"))
        assertTrue(("u42" to ITEM_ID) in itemRepository.items)
    }

    @Test
    fun `DELETE ohne oder mit ungueltiger X-Item-Id ergibt 400`() = itemTest {
        assertEquals(HttpStatusCode.BadRequest, deleteItem(itemId = null).status)
        assertEquals(HttpStatusCode.BadRequest, deleteItem(itemId = "a|b").status)
    }

    private suspend fun ApplicationTestBuilder.deleteItem(itemId: String? = ITEM_ID): HttpResponse = client.delete("/items") {
        callerHeaders()
        header(VAULT_TOKEN_HEADER, token)
        if (itemId != null) header(ITEM_ID_HEADER, itemId)
    }

    private suspend fun ApplicationTestBuilder.getSecret(itemId: String? = ITEM_ID): HttpResponse = client.get("/items/secret") {
        callerHeaders()
        header(VAULT_TOKEN_HEADER, token)
        if (itemId != null) header(ITEM_ID_HEADER, itemId)
    }

    private suspend fun ApplicationTestBuilder.getItems(): HttpResponse = client.get("/items") {
        callerHeaders()
        header(VAULT_TOKEN_HEADER, token)
    }

    private fun itemTest(block: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        environment { config = MapApplicationConfig() }
        vaults.sessions += session()
        application {
            configureApp(
                VaultService(vaults, keyService, cryptoService, clock),
                ItemService(itemRepository, CryptoServices(aes = aesService, chacha = cryptoService)),
                LoginTokenVerifier(FakeAuthService()),
            )
        }
        block()
    }

    private fun session(expiresAt: Instant = clock.instant().plus(Duration.ofMinutes(10))) =
        VaultSession(VaultToken.hash(token), "u42", "dev-mac-01", "s-1", expiresAt)

    private fun HttpRequestBuilder.callerHeaders() {
        header(HttpHeaders.Authorization, "Bearer $LOGIN_TOKEN")
        header(DEVICE_ID_HEADER, "dev-mac-01")
    }

    private suspend fun ApplicationTestBuilder.putItem(
        rev: Int,
        itemId: String? = ITEM_ID,
        head: ByteArray = HEAD,
        secret: ByteArray = SECRET,
        rawHead: String = b64(head),
        alg: String? = null,
    ): HttpResponse = client.put("/items") {
        callerHeaders()
        header(VAULT_TOKEN_HEADER, token)
        if (itemId != null) header(ITEM_ID_HEADER, itemId)
        contentType(ContentType.Application.Json)
        val algField = if (alg != null) ""","alg":"$alg"""" else ""
        setBody("""{"rev":$rev,"head":"$rawHead","secret":"${b64(secret)}"$algField}""")
    }

    private suspend fun HttpResponse.json(field: String): String =
        Json.parseToJsonElement(bodyAsText()).jsonObject.getValue(field).jsonPrimitive.content

    private suspend fun HttpResponse.rev(field: String = "rev"): Int =
        Json.parseToJsonElement(bodyAsText()).jsonObject.getValue(field).jsonPrimitive.int

    private companion object {
        const val ITEM_ID = "3f2a9c1e-7b4d-4e2a-9c1e-0a1b2c3d4e5f"

        // head: 128 byte padding block + 30 = 158 bytes, secret: 32 + 30 = 62 bytes (like in the docs)
        val HEAD = byteArrayOf(0x01, 0x01) + ByteArray(156) { 5 }
        val SECRET = byteArrayOf(0x01, 0x01) + ByteArray(60) { 6 }

        fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    }
}
