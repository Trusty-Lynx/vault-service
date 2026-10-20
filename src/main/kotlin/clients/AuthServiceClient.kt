package de.trustylynx.clients

import java.time.Instant

/** Zugriff auf den Auth-Service. Als Interface, damit Tests einen Fake einsetzen können. */
interface AuthServiceClient {
    /**
     * Prüft einen Login-Token über `POST /internal/sessions/verify`.
     * Token unbekannt, abgelaufen oder für ein anderes Gerät → null. Auth nicht erreichbar oder kaputte Antwort → UpstreamException.
     *
     * [deviceId] ist optional, weil die Geräte gerade aus dem Auth-Service ausgebaut werden (Umbau ohne Guard).
     * Ohne deviceId wird das Feld gar nicht erst mitgeschickt.
     */
    suspend fun verifySession(token: String, deviceId: String?): VerifiedSession?
}

/** Was der Auth-Service über eine gültige Login-Session sagt. */
class VerifiedSession(
    val userId: String,
    val sessionId: String,
    /** Fällt mit dem Umbau ohne Guard weg, deshalb nullable. */
    val deviceId: String?,
    val expiresAt: Instant,
)
