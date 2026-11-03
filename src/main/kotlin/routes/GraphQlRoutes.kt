package de.trustylynx.routes

import de.trustylynx.security.LoginTokenVerifier
import de.trustylynx.services.ItemService
import de.trustylynx.services.VaultService
import graphql.ExecutionInput
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import kotlinx.coroutines.future.await
import kotlinx.coroutines.supervisorScope
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

@Serializable
private data class GraphQlRequest(
    val query: String,
    val operationName: String? = null,
    val variables: JsonObject? = null,
)

// Always answers 200 with { data, errors }, errors from the services end up in `errors`.
// Only exception: without a valid login token it's a plain 401 like in REST and the query doesn't run at all.
fun Route.graphQlRoutes(vaultService: VaultService, itemService: ItemService, loginTokens: LoginTokenVerifier) {
    val graphQl = vaultGraphQl(vaultService, itemService)

    post("/graphql") {
        // once per request and not per field, otherwise a query with three fields asks the auth service three times
        val caller = loginTokens.verify(call)
        val request = call.receive<GraphQlRequest>()

        // supervisorScope: if one field fails, the others keep running and the error only ends up in `errors`
        val result = supervisorScope {
            val input = ExecutionInput.newExecutionInput()
                .query(request.query)
                .operationName(request.operationName)
                .variables(request.variables?.toPlain().orEmpty())
                .graphQLContext(mapOf<Any, Any>(GraphQlCall::class.java to GraphQlCall(caller, call.vaultToken(), this)))
                .build()
            graphQl.executeAsync(input).await()
        }
        call.respond(result.toSpecification().toJsonElement())
    }
}

// graphql-java works with Map/List/String/Number, we use kotlinx.serialization, so we translate both ways

internal fun Any?.toJsonElement(): JsonElement = when (this) {
    null -> JsonNull
    is JsonElement -> this
    is String -> JsonPrimitive(this)
    is Number -> JsonPrimitive(this)
    is Boolean -> JsonPrimitive(this)
    is Map<*, *> -> JsonObject(entries.associate { (key, value) -> key.toString() to value.toJsonElement() })
    is Iterable<*> -> JsonArray(map { it.toJsonElement() })
    else -> JsonPrimitive(toString())
}

private fun JsonObject.toPlain(): Map<String, Any?> = mapValues { it.value.toPlain() }

private fun JsonElement.toPlain(): Any? = when (this) {
    is JsonNull -> null
    is JsonObject -> toPlain()
    is JsonArray -> map { it.toPlain() }
    // whole numbers become Long, graphql-java turns them back into Int for Int fields.
    // "as Any?" is needed, otherwise the compiler looks for a common type of Boolean/Long/Double/String and crashes
    is JsonPrimitive -> if (isString) content else (booleanOrNull as Any?) ?: longOrNull ?: doubleOrNull ?: content
}
