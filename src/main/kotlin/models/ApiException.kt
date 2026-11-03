package de.trustylynx.models

import io.ktor.http.HttpStatusCode
import kotlinx.serialization.Serializable

open class ApiException(
    val status: HttpStatusCode,
    val code: String,
    val reason: String? = null,
) : RuntimeException(code, null, false, false)

class BadRequest(reason: String) : ApiException(HttpStatusCode.BadRequest, "bad_request", reason)

class Unauthorized : ApiException(HttpStatusCode.Unauthorized, "unauthorized")

// vault token missing, wrong or expired
class VaultLocked : ApiException(HttpStatusCode.Unauthorized, "vault_locked")

class Forbidden : ApiException(HttpStatusCode.Forbidden, "forbidden")

class NotFound : ApiException(HttpStatusCode.NotFound, "not_found")

class AlreadyExists : ApiException(HttpStatusCode.Conflict, "already_exists")

// currentRev 0 means the item doesn't exist. If currentRev equals the rev that was sent,
// an earlier attempt already went through
class RevConflict(val currentRev: Int) : ApiException(HttpStatusCode.Conflict, "rev_conflict")

class TooManyRequests(val retryAfterSeconds: Long) :
    ApiException(HttpStatusCode.TooManyRequests, "too_many_requests")

// wrong tag from the crypto service: someone changed data in the vault DB. That's a security incident, not an outage
class IntegrityError : ApiException(HttpStatusCode.InternalServerError, "integrity_error")

// another service didn't answer or sent garbage, ends up as 502
class UpstreamException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

// alg is "aes" or "chacha" and goes into the response, so the client can suggest the other service
class CryptoUnavailable(val alg: String, cause: UpstreamException) : RuntimeException(cause.message, cause)

@Serializable
data class RevConflictResponse(
    val error: String,
    val currentRev: Int,
)

@Serializable
data class ErrorResponse(
    val error: String,
    val reason: String? = null,
)
