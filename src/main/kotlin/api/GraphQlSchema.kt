package de.trustylynx.api

import de.trustylynx.common.ApiException
import de.trustylynx.common.AppJson
import de.trustylynx.common.BadRequest
import de.trustylynx.common.Caller
import de.trustylynx.common.CryptoUnavailable
import de.trustylynx.common.IntegrityError
import de.trustylynx.common.RevConflict
import de.trustylynx.common.UpstreamException
import de.trustylynx.common.isValidId
import de.trustylynx.common.toBase64
import de.trustylynx.domain.ItemService
import de.trustylynx.domain.VaultService
import de.trustylynx.validation.validate
import graphql.ErrorClassification
import graphql.ErrorType
import graphql.GraphQL
import graphql.GraphQLError
import graphql.execution.DataFetcherExceptionHandler
import graphql.execution.DataFetcherExceptionHandlerParameters
import graphql.execution.DataFetcherExceptionHandlerResult
import graphql.language.SourceLocation
import graphql.schema.DataFetcher
import graphql.schema.DataFetchingEnvironment
import graphql.schema.idl.RuntimeWiring
import graphql.schema.idl.SchemaGenerator
import graphql.schema.idl.SchemaParser
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.future.future
import kotlinx.serialization.json.decodeFromJsonElement
import org.slf4j.LoggerFactory
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException

/**
 * Was jeder Resolver über die HTTP-Anfrage wissen muss. Der Login-Token ist schon geprüft (in der Route, einmal pro Anfrage),
 * den Tresor-Token prüft jeder Resolver hinter dem Entsperren selbst, wie die REST-Routen auch.
 * [scope]: darin laufen die suspend-Aufrufe der Resolver (graphql-java selbst kennt nur CompletableFuture).
 */
internal class GraphQlCall(
    val caller: Caller,
    val vaultToken: String?,
    val scope: CoroutineScope,
)

/**
 * Baut die GraphQL-Engine aus `resources/graphql/schema.graphqls` (Schema-first).
 * Die Resolver machen dasselbe wie die REST-Routen: api → validation → domain, gleiche Response-Klassen aus Dtos.kt.
 */
internal fun vaultGraphQl(vaultService: VaultService, itemService: ItemService): GraphQL {
    val sdl = GraphQlCall::class.java.getResource("/graphql/schema.graphqls")!!.readText()

    val wiring = RuntimeWiring.newRuntimeWiring()
        .type("Query") { type ->
            type
                .dataFetcher("vaultParams", resolver { _, call ->
                    val params = vaultService.params(call.caller)
                    VaultParamsResponse(salt = params.saltVault.toBase64(), kdf = params.kdf)
                })
                .dataFetcher("items", resolver { _, call ->
                    val caller = call.unlockedCaller(vaultService)
                    itemService.listHeads(caller).map {
                        ItemHeadResponse(id = it.itemId, rev = it.rev, head = it.head.toBase64(), alg = it.alg.wire)
                    }
                })
                .dataFetcher("itemSecret", resolver { env, call ->
                    val caller = call.unlockedCaller(vaultService)
                    val secret = itemService.secret(caller, env.itemId())
                    ItemSecretResponse(data = secret.secret.toBase64(), rev = secret.rev)
                })
        }
        .type("Mutation") { type ->
            type
                .dataFetcher("createVault", resolver { env, call ->
                    val vault = env.input<CreateVaultRequest>().validate(call.caller)
                    CreateVaultResponse(vaultService.create(vault))
                })
                .dataFetcher("unlockVault", resolver { env, call ->
                    val unlockKey = UnlockVaultRequest(env.argument("unlockKey")).validate()
                    val unlocked = vaultService.unlock(call.caller, unlockKey)
                    UnlockVaultResponse(
                        vaultToken = unlocked.vaultToken,
                        expiresIn = unlocked.expiresIn.seconds,
                        wdek = unlocked.wdek.toBase64(),
                    )
                })
                .dataFetcher("lockVault", resolver { _, call ->
                    vaultService.lock(call.caller, call.vaultToken)
                    true
                })
                .dataFetcher("putItem", resolver { env, call ->
                    val caller = call.unlockedCaller(vaultService)
                    val item = env.input<PutItemRequest>().validate(env.itemId())
                    PutItemResponse(rev = itemService.put(caller, item))
                })
                .dataFetcher("deleteItem", resolver { env, call ->
                    val caller = call.unlockedCaller(vaultService)
                    itemService.delete(caller, env.itemId())
                    true
                })
        }
        .build()

    val schema = SchemaGenerator().makeExecutableSchema(SchemaParser().parse(sdl), wiring)
    return GraphQL.newGraphQL(schema)
        .defaultDataFetcherExceptionHandler(GraphQlErrorHandler)
        .build()
}

/**
 * Resolver mit suspend-Block. Läuft im Scope der Anfrage, damit Request-ID (MDC) und Abbruch mitgehen.
 * Any? reicht, graphql-java braucht den Ergebnistyp nicht.
 */
private fun resolver(block: suspend (DataFetchingEnvironment, GraphQlCall) -> Any?): DataFetcher<CompletableFuture<Any?>> =
    DataFetcher { env ->
        val call = checkNotNull(env.graphQlContext.get<GraphQlCall>(GraphQlCall::class.java)) { "GraphQlCall missing in context" }
        call.scope.future { block(env, call) }
    }

/** Wie unlockedCaller() in ItemRoutes: Tresor-Token prüfen, bevor irgendetwas über Einträge verraten wird. */
private suspend fun GraphQlCall.unlockedCaller(vaultService: VaultService): Caller =
    caller.also { vaultService.requireUnlocked(it, vaultToken) }

private fun <T : Any> DataFetchingEnvironment.argument(name: String): T =
    getArgument<T>(name) ?: throw BadRequest("missing $name")

/** Die itemId als Argument statt Header X-Item-Id, gleiche Prüfung wie ApplicationCall.itemId(). */
private fun DataFetchingEnvironment.itemId(): String =
    argument<String>("itemId").also { if (!isValidId(it)) throw BadRequest("invalid itemId") }

/** Input-Objekt (kommt als Map) in die bestehende Request-Klasse aus Dtos.kt, damit dieselbe validate() greift. */
private inline fun <reified T> DataFetchingEnvironment.input(): T =
    AppJson.decodeFromJsonElement<T>(argument<Map<String, Any?>>("input").toJsonElement())

/**
 * Gegenstück zu StatusPages für GraphQL: Fehler gehen nicht als HTTP-Status raus, sondern als Eintrag in `errors`.
 * `extensions.code` ist derselbe Code wie bei REST (`vault_locked`, `not_found`, `rev_conflict`, …),
 * `extensions.status` der HTTP-Status, den REST geschickt hätte. Andere Felder im selben Request laufen weiter.
 */
private object GraphQlErrorHandler : DataFetcherExceptionHandler {
    private val log = LoggerFactory.getLogger("de.trustylynx.api.GraphQL")

    override fun handleException(params: DataFetcherExceptionHandlerParameters): CompletableFuture<DataFetcherExceptionHandlerResult> {
        // Aus dem future { } kommt die Exception manchmal verpackt.
        val cause = params.exception.let { if (it is CompletionException) it.cause ?: it else it }
        val path = params.path.toString()

        val extensions: Map<String, Any> = when (cause) {
            is ApiException -> {
                if (cause is IntegrityError) log.error("Integrity error on GraphQL $path")
                buildMap<String, Any> {
                    put("code", cause.code)
                    put("status", cause.status.value)
                    cause.reason?.let { put("reason", it) }
                    if (cause is RevConflict) put("currentRev", cause.currentRev)
                }
            }
            is CryptoUnavailable -> {
                log.error("Crypto service ${cause.alg} unavailable on GraphQL $path", cause)
                mapOf<String, Any>("code" to "crypto_unavailable", "status" to 502, "reason" to cause.alg)
            }
            is UpstreamException -> {
                log.error("Upstream error on GraphQL $path", cause)
                mapOf<String, Any>("code" to "upstream_error", "status" to 502)
            }
            else -> {
                log.error("Unhandled error on GraphQL $path", cause)
                mapOf<String, Any>("code" to "internal_error", "status" to 500)
            }
        }

        val error = VaultGraphQlError(extensions, params.path.toList(), listOfNotNull(params.sourceLocation))
        return CompletableFuture.completedFuture(DataFetcherExceptionHandlerResult.newResult(error).build())
    }
}

/**
 * Ein Eintrag in `errors`. Eigene Klasse statt GraphqlErrorBuilder: dessen rekursiver Typparameter
 * (B extends GraphqlErrorBuilder<B>) lässt den Kotlin-Compiler 2.4 mit StackOverflowError abstürzen.
 */
private class VaultGraphQlError(
    private val extensions: Map<String, Any>,
    private val path: List<Any>,
    private val locations: List<SourceLocation>,
) : GraphQLError {
    override fun getMessage(): String = extensions["code"] as String
    override fun getLocations(): List<SourceLocation> = locations
    override fun getErrorType(): ErrorClassification = ErrorType.DataFetchingException
    override fun getPath(): List<Any> = path
    override fun getExtensions(): Map<String, Any> = extensions
}
