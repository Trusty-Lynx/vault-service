package de.trustylynx.common

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
            // Manipulationsverdacht: muss im Log auffallen (Audit-Log ist gestrichen).
            if (cause is IntegrityError) {
                call.application.log.error("Integrity error on ${call.request.httpMethod.value} ${call.request.path()}")
            }
            call.respond(cause.status, ErrorResponse(cause.code, cause.reason))
        }
        // Kaputtes oder unvollständiges JSON bei call.receive()
        exception<BadRequestException> { call, _ ->
            call.respond(HttpStatusCode.BadRequest, ErrorResponse("bad_request", "malformed request body"))
        }
        exception<UpstreamException> { call, cause ->
            call.application.log.error("Upstream error on ${call.request.httpMethod.value} ${call.request.path()}", cause)
            call.respond(HttpStatusCode.BadGateway, ErrorResponse("upstream_error"))
        }
        exception<Throwable> { call, cause ->
            // Ktor-eigene Fehler (404, 415, 413, …) behalten ihren Status.
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
