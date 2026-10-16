package de.trustylynx.common

import io.ktor.http.HttpStatusCode
import kotlinx.serialization.Serializable

/** Fachlicher Fehler, den StatusPages in eine 4xx-Response mit [ErrorResponse] übersetzt. */
sealed class ApiException(
    val status: HttpStatusCode,
    val code: String,
    val reason: String? = null,
) : RuntimeException(code, null, false, false)

class BadRequest(reason: String) : ApiException(HttpStatusCode.BadRequest, "bad_request", reason)

class Unauthorized : ApiException(HttpStatusCode.Unauthorized, "unauthorized")

/** Tresor-Token fehlt, passt nicht oder ist abgelaufen. */
class VaultLocked : ApiException(HttpStatusCode.Unauthorized, "vault_locked")

class Forbidden : ApiException(HttpStatusCode.Forbidden, "forbidden")

class NotFound : ApiException(HttpStatusCode.NotFound, "not_found")

class AlreadyExists : ApiException(HttpStatusCode.Conflict, "already_exists")

class TooManyRequests(val retryAfterSeconds: Long) :
    ApiException(HttpStatusCode.TooManyRequests, "too_many_requests")

/** Ein anderer Service hat nicht oder unbrauchbar geantwortet. Wird zu 502. */
class UpstreamException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

@Serializable
data class ErrorResponse(
    val error: String,
    val reason: String? = null,
)
