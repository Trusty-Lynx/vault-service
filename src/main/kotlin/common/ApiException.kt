package de.trustylynx.common

import io.ktor.http.HttpStatusCode
import kotlinx.serialization.Serializable

/** Fachlicher Fehler, den StatusPages in eine Response mit [ErrorResponse] übersetzt (meist 4xx). */
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

/**
 * Der Crypto-Service meldet einen falschen Tag: Die Daten in der Vault-DB wurden manipuliert oder untergeschoben.
 * Kein normaler Ausfall, sondern ein Sicherheitsvorfall → 500 integrity_error und Log-Eintrag.
 */
class IntegrityError : ApiException(HttpStatusCode.InternalServerError, "integrity_error")

/** Ein anderer Service hat nicht oder unbrauchbar geantwortet. Wird zu 502. */
class UpstreamException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

@Serializable
data class ErrorResponse(
    val error: String,
    val reason: String? = null,
)
