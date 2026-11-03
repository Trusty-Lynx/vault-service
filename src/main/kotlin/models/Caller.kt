package de.trustylynx.models

private val ID = Regex("^[A-Za-z0-9._-]{1,128}$")

// same format for userId, deviceId, sessionId and itemId, no matter if they come from a header or the auth service
fun isValidId(value: String): Boolean = ID.matches(value)

// stored when there's no X-Device-Id. The vault token is then bound to user and login session, but not to a device.
// TODO: remove and make X-Device-Id required once all clients send it
const val NO_DEVICE_ID = "no-device"

// only ever comes from the verified login token, never from the body
class Caller(
    val userId: String,
    val deviceId: String,
    val sessionId: String,
)
