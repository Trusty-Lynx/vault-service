package de.trustylynx.api

import de.trustylynx.domain.ItemService
import de.trustylynx.domain.VaultService
import de.trustylynx.security.LoginTokenVerifier
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

/** Body von POST /graphql laut GraphQL-over-HTTP. */
@Serializable
data class GraphQlRequest(
    val query: String,
    val operationName: String? = null,
    val variables: JsonObject? = null,
)

/**
 * POST /graphql (#36): dieselben Funktionen wie die REST-Routen, nur als eine Abfrage.
 * Die Antwort ist immer `{ data, errors }` mit 200, fachliche Fehler stehen in `errors` (siehe GraphQlErrorHandler).
 * Ausnahme: Ohne gültigen Login-Token gibt es wie bei REST direkt `401 unauthorized`, ohne die Abfrage auszuführen.
 */
fun Route.graphQlRoutes(vaultService: VaultService, itemService: ItemService, loginTokens: LoginTokenVerifier) {
    val graphQl = vaultGraphQl(vaultService, itemService)

    post("/graphql") {
        // Einmal pro Anfrage, nicht pro Feld: sonst fragt eine Abfrage mit drei Feldern dreimal den Auth-Service.
        val caller = loginTokens.verify(call)
        val request = call.receive<GraphQlRequest>()

        // supervisorScope: Scheitert ein Feld, laufen die anderen weiter, der Fehler landet nur in `errors`.
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

// graphql-java arbeitet mit Map/List/String/Number, Ktor bei uns mit kotlinx.serialization. Hier die Übersetzung in beide Richtungen.

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
    // Zahlen ohne Nachkommastellen als Long, graphql-java macht daraus bei Int-Feldern wieder Int.
    // "as Any?" ist nötig: sonst sucht der Compiler den gemeinsamen Typ von Boolean/Long/Double/String und stürzt ab.
    is JsonPrimitive -> if (isString) content else (booleanOrNull as Any?) ?: longOrNull ?: doubleOrNull ?: content
}
