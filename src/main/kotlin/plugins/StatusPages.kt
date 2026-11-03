package de.trustylynx.plugins

import de.trustylynx.models.ApiException
import de.trustylynx.models.CryptoUnavailable
import de.trustylynx.models.ErrorResponse
import de.trustylynx.models.IntegrityError
import de.trustylynx.models.RevConflict
import de.trustylynx.models.RevConflictResponse
import de.trustylynx.models.TooManyRequests
import de.trustylynx.models.UpstreamException
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.engine.defaultExceptionStatusCode
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.header
import io.ktor.server.response.respond

fun Application.configureStatusPages() {
    install(StatusPages) {
        exception<ApiException> { call, cause ->
            if (cause is TooManyRequests) {
                call.response.header(HttpHeaders.RetryAfter, cause.retryAfterSeconds.toString())
            }
            // possible tampering has to stand out in the log, there's no audit log anymore
            if (cause is IntegrityError) {
                call.application.log.error("Integrity error on ${call.request.httpMethod.value} ${call.request.path()}")
            }
            if (cause is RevConflict) {
                call.respond(cause.status, RevConflictResponse(cause.code, cause.currentRev))
                return@exception
            }
            call.respond(cause.status, ErrorResponse(cause.code, cause.reason))
        }
        // broken or incomplete JSON in call.receive()
        exception<BadRequestException> { call, _ ->
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("bad_request", "malformed request body"))
        }
        exception<CryptoUnavailable> { call, cause ->
            call.application.log.error("Crypto service ${cause.alg} unavailable on ${call.request.httpMethod.value} ${call.request.path()}", cause)
            call.respond(HttpStatusCode.BadGateway, ErrorResponse("crypto_unavailable", cause.alg))
        }
        exception<UpstreamException> { call, cause ->
            call.application.log.error("Upstream error on ${call.request.httpMethod.value} ${call.request.path()}", cause)
            call.respond(HttpStatusCode.BadGateway, ErrorResponse("upstream_error"))
        }
        exception<Throwable> { call, cause ->
            // Ktor's own errors (404, 415, 413, ...) keep their status
            val status = defaultExceptionStatusCode(cause)
            if (status != null) {
                call.respond(status, ErrorResponse(status.description.lowercase().replace(' ', '_')))
                return@exception
            }
            call.application.log.error("Unhandled error on ${call.request.httpMethod.value} ${call.request.path()}", cause)
            call.respond(HttpStatusCode.InternalServerError, ErrorResponse("internal_error"))
        }
    }
}
