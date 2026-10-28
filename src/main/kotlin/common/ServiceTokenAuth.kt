package de.trustylynx.common

import io.ktor.server.application.ApplicationCall
import java.security.MessageDigest

/** Prüft den Header `X-Service-Token` eines internen Aufrufs. Fehlt er oder ist er falsch, gibt es 403. */
fun ApplicationCall.requireServiceToken(expectedToken: String) {
    val provided = request.headers[SERVICE_TOKEN_HEADER] ?: throw Forbidden()
    if (!constantTimeEquals(provided, expectedToken)) throw Forbidden()
}

// Erst hashen, damit auch Tokens unterschiedlicher Länge in konstanter Zeit verglichen werden.
private fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(sha256(a.toByteArray()), sha256(b.toByteArray()))
