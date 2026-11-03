package de.trustylynx.security

import de.trustylynx.models.Forbidden
import de.trustylynx.models.SERVICE_TOKEN_HEADER
import io.ktor.server.application.ApplicationCall
import java.security.MessageDigest

fun ApplicationCall.requireServiceToken(expectedToken: String) {
    val provided = request.headers[SERVICE_TOKEN_HEADER] ?: throw Forbidden()
    if (!constantTimeEquals(provided, expectedToken)) throw Forbidden()
}

// hash first, so tokens of different length are compared in constant time too
private fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(sha256(a.toByteArray()), sha256(b.toByteArray()))
