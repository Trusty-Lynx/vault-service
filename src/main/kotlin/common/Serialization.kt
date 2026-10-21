package de.trustylynx.common

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import kotlinx.serialization.json.Json
import java.util.Base64

/** JSON für die eigene API (Requests und Responses). */
val AppJson = Json {
    explicitNulls = false
    encodeDefaults = true
}

/** JSON für Aufrufe an andere Services: tolerant gegenüber neuen Feldern. */
val ServiceJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
}

fun Application.configureSerialization() {
    install(ContentNegotiation) {
        json(AppJson)
    }
}

fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)

fun String.decodeBase64OrNull(): ByteArray? = try {
    Base64.getDecoder().decode(this)
} catch (_: IllegalArgumentException) {
    null
}
