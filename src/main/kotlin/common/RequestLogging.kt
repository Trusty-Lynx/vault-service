package de.trustylynx.common

import io.ktor.http.HttpHeaders
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.callid.CallId
import io.ktor.server.plugins.callid.callIdMdc
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import java.util.UUID

// Wie im auth-service: Jede Anfrage bekommt eine X-Request-Id (oder übernimmt die mitgeschickte).
// Sie steht in jeder Logzeile (MDC requestId) und geht über den HTTP-Client an Key- und Crypto-Service weiter.
private val REQUEST_ID = Regex("^[A-Za-z0-9._-]{1,128}$")

fun Application.configureRequestLogging() {
    install(CallId) {
        retrieveFromHeader(HttpHeaders.XRequestId)
        generate { UUID.randomUUID().toString() }
        verify { REQUEST_ID.matches(it) }
        replyToHeader(HttpHeaders.XRequestId)
    }
    install(CallLogging) {
        callIdMdc("requestId")
        filter { it.request.path() != HEALTH_PATH }
        format { call -> "${call.response.status()?.value} ${call.request.httpMethod.value} ${call.request.path()}" }
    }
}
