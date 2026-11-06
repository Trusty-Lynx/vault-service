package de.trustylynx.routes

import de.trustylynx.models.ApiException
import de.trustylynx.models.BadRequest
import de.trustylynx.models.Caller
import de.trustylynx.models.CreateVaultRequest
import de.trustylynx.models.CryptoUnavailable
import de.trustylynx.models.IntegrityError
import de.trustylynx.models.PutItemRequest
import de.trustylynx.models.RevConflict
import de.trustylynx.models.UpstreamException
import de.trustylynx.models.isValidId
import de.trustylynx.plugins.AppJson
import de.trustylynx.services.ItemService
import de.trustylynx.services.VaultService
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

// The login token is already checked in the route, the vault token is checked by every resolver that needs it,
// like the REST routes do. scope runs the suspend calls, graphql-java itself only knows CompletableFuture
internal class GraphQlCall(
    val caller: Caller,
    val vaultToken: String?,
    val scope: CoroutineScope,
)

// the resolvers do the same as the REST routes: same checks in the same order, same services, same responses
internal fun vaultGraphQl(vaultService: VaultService, itemService: ItemService): GraphQL {
    val sdl = GraphQlCall::class.java.getResource("/graphql/schema.graphqls")!!.readText()

    val wiring = RuntimeWiring.newRuntimeWiring()
        .type("Query") { type ->
            type
                .dataFetcher("vaultParams", resolver { _, call ->
                    vaultService.params(call.caller)
                })
                .dataFetcher("items", resolver { _, call ->
                    itemService.listHeads(call.unlockedCaller(vaultService))
                })
                .dataFetcher("itemSecret", resolver { env, call ->
                    val caller = call.unlockedCaller(vaultService)
                    itemService.secret(caller, env.itemId())
                })
        }
        .type("Mutation") { type ->
            type
                .dataFetcher("createVault", resolver { env, call ->
                    val request = env.input<CreateVaultRequest>()
                    vaultService.create(
                        caller = call.caller,
                        saltVault = validateBase64(request.salt, SALT_VAULT_LENGTH),
                        kdf = validateKdf(request.kdf),
                        unlockKey = validateUnlockKey(request.unlockKey),
                        wdek = validateWdek(request.wdek),
                    )
                })
                .dataFetcher("unlockVault", resolver { env, call ->
                    vaultService.unlock(call.caller, validateUnlockKey(env.argument("unlockKey")))
                })
                .dataFetcher("lockVault", resolver { _, call ->
                    vaultService.lock(call.caller, call.vaultToken)
                    true
                })
                .dataFetcher("putItem", resolver { env, call ->
                    val caller = call.unlockedCaller(vaultService)
                    val request = env.input<PutItemRequest>()
                    itemService.put(
                        caller = caller,
                        itemId = env.itemId(),
                        rev = validateRev(request.rev),
                        head = validateC1(request.head, "head"),
                        secret = validateC1(request.secret, "secret"),
                        alg = validateAlg(request.alg),
                    )
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

// runs in the scope of the request, so the request id (MDC) and cancellation carry over
private fun resolver(block: suspend (DataFetchingEnvironment, GraphQlCall) -> Any?): DataFetcher<CompletableFuture<Any?>> =
    DataFetcher { env ->
        val call = checkNotNull(env.graphQlContext.get<GraphQlCall>(GraphQlCall::class.java)) { "GraphQlCall missing in context" }
        call.scope.future { block(env, call) }
    }

// check the vault token before anything about items is revealed, same as in ItemRoutes
private suspend fun GraphQlCall.unlockedCaller(vaultService: VaultService): Caller {
    vaultService.requireUnlocked(caller, vaultToken)
    return caller
}

private fun <T : Any> DataFetchingEnvironment.argument(name: String): T =
    getArgument<T>(name) ?: throw BadRequest("missing $name")

// argument instead of the X-Item-Id header, same check as ApplicationCall.itemId()
private fun DataFetchingEnvironment.itemId(): String {
    val itemId = argument<String>("itemId")
    if (!isValidId(itemId)) throw BadRequest("invalid itemId")
    return itemId
}

// the input comes as a Map, turned into the same request class as in REST
private inline fun <reified T> DataFetchingEnvironment.input(): T =
    AppJson.decodeFromJsonElement<T>(argument<Map<String, Any?>>("input").toJsonElement())

// Like StatusPages, but errors go into `errors` instead of the HTTP status. extensions.code is the same code
// as in REST, extensions.status the status REST would have sent
private object GraphQlErrorHandler : DataFetcherExceptionHandler {
    private val log = LoggerFactory.getLogger("de.trustylynx.routes.GraphQL")

    override fun handleException(params: DataFetcherExceptionHandlerParameters): CompletableFuture<DataFetcherExceptionHandlerResult> {
        // exceptions from future { } sometimes come wrapped
        val cause = params.exception.let { if (it is CompletionException) it.cause ?: it else it }
        val path = params.path.toString()

        val extensions: Map<String, Any> = when (cause) {
            is ApiException -> {
                if (cause is IntegrityError) log.error("Integrity error on GraphQL $path")
                buildMap<String, Any> {
                    put("code", cause.code)
                    put("status", cause.status.value)
                    if (cause.reason != null) put("reason", cause.reason)
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

// own class instead of GraphqlErrorBuilder, its recursive type parameter (B extends GraphqlErrorBuilder<B>)
// crashes the Kotlin 2.4 compiler with a StackOverflowError
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
