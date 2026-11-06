package de.trustylynx.models

private val ID = Regex("^[A-Za-z0-9._-]{1,128}$")

// same format for userId, sessionId and itemId, no matter if they come from a header or the auth service
fun isValidId(value: String): Boolean = ID.matches(value)

// only ever comes from the verified login token, never from the body
class Caller(
    val userId: String,
    val sessionId: String,
)
