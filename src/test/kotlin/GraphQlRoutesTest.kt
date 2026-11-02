package de.trustylynx

import de.trustylynx.clients.CryptoAlg
import de.trustylynx.clients.CryptoServices
import de.trustylynx.common.DEVICE_ID_HEADER
import de.trustylynx.common.VAULT_TOKEN_HEADER
import de.trustylynx.domain.ItemService
import de.trustylynx.domain.KdfParams
import de.trustylynx.domain.StoredItem
import de.trustylynx.domain.Vault
import de.trustylynx.domain.VaultService
import de.trustylynx.domain.VaultSession
import de.trustylynx.security.LoginTokenVerifier
import de.trustylynx.security.VaultToken
import de.trustylynx.security.VerifierHasher
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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// POST /graphql (#36). Gleiche Fakes wie VaultRoutesTest und ItemRoutesTest, geprüft wird vor allem:
// gleiche Funktionen wie REST, gleiche Fehlercodes (in errors[].extensions), gleiche Reihenfolge der Prüfungen.
class GraphQlRoutesTest {

    private val vaults = FakeVaultRepository()
    private val itemRepository = FakeItemRepository()
    private val keyService = FakeKeyService()
    private val cryptoService = FakeCryptoService()
    private val aesService = FakeCryptoService(CryptoAlg.AES)
    private val auth = FakeAuthService()
    private val clock = Clock.fixed(Instant.parse("2026-11-02T12:00:00Z"), ZoneOffset.UTC)
    private val token = VaultToken.generate()

    // ---------- Login-Token ----------

    @Test
    fun `ohne Login-Token gibt es wie bei REST direkt 401, die Abfrage laeuft nicht`() = graphQlTest {
        val response = client.post("/graphql") {
            contentType(ContentType.Application.Json)
            setBody(body("{ items { id } }"))
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertTrue(response.bodyAsText().contains("unauthorized"))
        assertEquals(0, auth.calls)
    }

    @Test
    fun `mehrere Felder in einer Abfrage pruefen den Login-Token nur einmal`() = graphQlTest {
        storeItem()

        val response = graphQl("""{ items { id } itemSecret(itemId: "$ITEM_ID") { rev } }""")

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(1, auth.calls)
    }

    // ---------- Tresor ----------

    @Test
    fun `createVault legt den Tresor an und liefert den Tresor-Token`() = graphQlTest {
        vaults.sessions.clear()
        val variables = buildJsonObject {
            put("input", buildJsonObject {
                put("salt", b64(SALT_VAULT))
                put("kdf", buildJsonObject { put("alg", "argon2id"); put("m", 65536); put("t", 3); put("p", 1); put("len", 32) })
                put("unlockKey", b64(UNLOCK_KEY))
                put("wdek", b64(WDEK))
            })
        }

        val response = graphQl(
            "mutation(\$input: CreateVaultInput!) { createVault(input: \$input) { vaultToken } }",
            variables,
        )

        val vaultToken = response.data().obj("createVault").string("vaultToken")
        assertTrue(VaultToken.isWellFormed(vaultToken))
        assertContentEquals(SALT_VAULT, assertNotNull(vaults.vault).saltVault)
        assertContentEquals(VaultToken.hash(vaultToken), vaults.sessions.single().tokenHash)
    }

    @Test
    fun `createVault mit falschem wdek ergibt bad_request wie bei REST`() = graphQlTest {
        val response = graphQl(
            """mutation { createVault(input: {salt: "${b64(SALT_VAULT)}", kdf: {alg: "argon2id", m: 65536, t: 3, p: 1, len: 32},
               unlockKey: "${b64(UNLOCK_KEY)}", wdek: "AAAA"}) { vaultToken } }""",
        )

        assertEquals("bad_request", response.errorCode())
        assertEquals(400, response.error().obj("extensions").getValue("status").jsonPrimitive.int)
    }

    @Test
    fun `vaultParams liefert Salt und KDF`() = graphQlTest {
        vaults.vault = storedVault()

        val params = graphQl("{ vaultParams { salt kdf { alg m t p len } } }").data().obj("vaultParams")

        assertEquals(b64(SALT_VAULT), params.string("salt"))
        assertEquals(65536, params.obj("kdf").getValue("m").jsonPrimitive.int)
    }

    @Test
    fun `vaultParams ohne Tresor ergibt not_found`() = graphQlTest {
        val response = graphQl("{ vaultParams { salt } }")

        assertEquals("not_found", response.errorCode())
        assertEquals(JsonNull, response.data().getValue("vaultParams"))
    }

    @Test
    fun `unlockVault mit richtigem unlockKey liefert wDEK und neuen Tresor-Token`() = graphQlTest {
        vaults.vault = storedVault()

        val unlocked = graphQl("""mutation { unlockVault(unlockKey: "${b64(UNLOCK_KEY)}") { vaultToken expiresIn wdek } }""")
            .data().obj("unlockVault")

        assertEquals(b64(WDEK), unlocked.string("wdek"))
        assertEquals(900, unlocked.getValue("expiresIn").jsonPrimitive.int)
        assertTrue(VaultToken.isWellFormed(unlocked.string("vaultToken")))
    }

    @Test
    fun `unlockVault mit falschem unlockKey ergibt unauthorized`() = graphQlTest {
        vaults.vault = storedVault()

        val response = graphQl("""mutation { unlockVault(unlockKey: "${b64(ByteArray(32) { 9 })}") { vaultToken } }""")

        assertEquals("unauthorized", response.errorCode())
    }

    @Test
    fun `lockVault widerruft den Tresor-Token, danach ist er ungueltig`() = graphQlTest {
        assertEquals(true, graphQl("mutation { lockVault }").data().getValue("lockVault").jsonPrimitive.content.toBoolean())
        assertTrue(vaults.sessions.isEmpty())

        assertEquals("vault_locked", graphQl("mutation { lockVault }").errorCode())
    }

    // ---------- Einträge ----------

    @Test
    fun `items und itemSecret in einer Abfrage`() = graphQlTest {
        storeItem()

        val data = graphQl("""{ items { id rev head alg } itemSecret(itemId: "$ITEM_ID") { data rev } }""").data()

        val head = data.getValue("items").jsonArray.single().jsonObject
        assertEquals(ITEM_ID, head.string("id"))
        assertEquals(b64(HEAD), head.string("head"))
        assertEquals("chacha", head.string("alg"))
        assertEquals(b64(SECRET), data.obj("itemSecret").string("data"))
    }

    @Test
    fun `ohne Tresor-Token ergibt vault_locked und verraet nichts ueber Eintraege`() = graphQlTest {
        storeItem()

        val response = graphQl("{ items { id } }", vaultToken = null)

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("vault_locked", response.errorCode())
        assertEquals(401, response.error().obj("extensions").getValue("status").jsonPrimitive.int)
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `putItem legt einen Eintrag mit rev 1 an, mit gewaehltem Crypto-Service`() = graphQlTest {
        val response = graphQl(
            """mutation { putItem(itemId: "$ITEM_ID", input: {rev: 1, head: "${b64(HEAD)}", secret: "${b64(SECRET)}", alg: "aes"}) { rev } }""",
        )

        assertEquals(1, response.data().obj("putItem").getValue("rev").jsonPrimitive.int)
        val stored = itemRepository.items.getValue("u42" to ITEM_ID)
        assertContentEquals(FakeCryptoService.c2Of(HEAD, CryptoAlg.AES), stored.headC2)
        assertTrue(cryptoService.calls.isEmpty())
    }

    @Test
    fun `putItem mit falscher rev ergibt rev_conflict mit currentRev`() = graphQlTest {
        storeItem()

        val response = graphQl(
            """mutation { putItem(itemId: "$ITEM_ID", input: {rev: 1, head: "${b64(HEAD)}", secret: "${b64(SECRET)}"}) { rev } }""",
        )

        assertEquals("rev_conflict", response.errorCode())
        assertEquals(1, response.error().obj("extensions").getValue("currentRev").jsonPrimitive.int)
    }

    @Test
    fun `deleteItem loescht, beim zweiten Mal not_found`() = graphQlTest {
        storeItem()

        assertEquals("true", graphQl("""mutation { deleteItem(itemId: "$ITEM_ID") }""").data().getValue("deleteItem").jsonPrimitive.content)
        assertTrue(itemRepository.items.isEmpty())
        assertEquals("not_found", graphQl("""mutation { deleteItem(itemId: "$ITEM_ID") }""").errorCode())
    }

    @Test
    fun `ungueltige itemId ergibt bad_request`() = graphQlTest {
        assertEquals("bad_request", graphQl("""{ itemSecret(itemId: "a/b") { rev } }""").errorCode())
    }

    @Test
    fun `Crypto-Service nicht erreichbar ergibt crypto_unavailable mit dem Dienst`() = graphQlTest {
        storeItem()
        cryptoService.fail = true

        val response = graphQl("{ items { id } }")

        assertEquals("crypto_unavailable", response.errorCode())
        assertEquals("chacha", response.error().obj("extensions").string("reason"))
    }

    @Test
    fun `scheitert ein Feld, kommen die anderen trotzdem`() = graphQlTest {
        storeItem()

        val response = graphQl("""{ items { id } itemSecret(itemId: "gibt-es-nicht") { rev } }""")

        assertEquals("not_found", response.errorCode())
        assertEquals(1, response.data().getValue("items").jsonArray.size)
    }

    @Test
    fun `Syntaxfehler in der Abfrage ergibt einen GraphQL-Fehler statt 500`() = graphQlTest {
        val response = graphQl("{ items { id ")

        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.json().getValue("errors").jsonArray.isNotEmpty())
    }

    // ---------- Hilfen ----------

    private fun graphQlTest(block: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        environment { config = MapApplicationConfig() }
        vaults.sessions += VaultSession(VaultToken.hash(token), "u42", "dev-mac-01", "s-1", clock.instant().plus(Duration.ofMinutes(10)))
        application {
            configureApp(
                VaultService(vaults, keyService, cryptoService, clock),
                ItemService(itemRepository, CryptoServices(aes = aesService, chacha = cryptoService)),
                LoginTokenVerifier(auth),
            )
        }
        block()
    }

    private suspend fun ApplicationTestBuilder.graphQl(
        query: String,
        variables: JsonObject? = null,
        vaultToken: String? = token,
    ): HttpResponse = client.post("/graphql") {
        header(HttpHeaders.Authorization, "Bearer $LOGIN_TOKEN")
        header(DEVICE_ID_HEADER, "dev-mac-01")
        if (vaultToken != null) header(VAULT_TOKEN_HEADER, vaultToken)
        contentType(ContentType.Application.Json)
        setBody(body(query, variables))
    }

    private fun body(query: String, variables: JsonObject? = null): String = buildJsonObject {
        put("query", query)
        if (variables != null) put("variables", variables)
    }.toString()

    private fun storeItem() {
        itemRepository.items["u42" to ITEM_ID] = StoredItem(ITEM_ID, 1, FakeCryptoService.c2Of(HEAD), FakeCryptoService.c2Of(SECRET))
    }

    /** Ein Tresor, wie createVault ihn mit UNLOCK_KEY und WDEK angelegt hätte. */
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

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject

    private suspend fun HttpResponse.data(): JsonObject = json().obj("data")

    private suspend fun HttpResponse.error(): JsonObject = (json().getValue("errors") as JsonArray).single().jsonObject

    private suspend fun HttpResponse.errorCode(): String = error().obj("extensions").string("code")

    private fun JsonObject.obj(field: String): JsonObject = getValue(field).jsonObject

    private fun JsonObject.string(field: String): String = (getValue(field) as JsonElement).jsonPrimitive.content

    private companion object {
        const val ITEM_ID = "3f2a9c1e-7b4d-4e2a-9c1e-0a1b2c3d4e5f"
        val SALT_VAULT = ByteArray(16) { 1 }
        val UNLOCK_KEY = ByteArray(32) { 2 }
        val WDEK = byteArrayOf(0x01, 0x01) + ByteArray(60) { 3 }

        // Kopf: 128 Byte Padding-Block + 30 = 158 Byte, Geheimnis: 32 + 30 = 62 Byte (wie in ItemRoutesTest)
        val HEAD = byteArrayOf(0x01, 0x01) + ByteArray(156) { 5 }
        val SECRET = byteArrayOf(0x01, 0x01) + ByteArray(60) { 6 }

        fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    }
}
