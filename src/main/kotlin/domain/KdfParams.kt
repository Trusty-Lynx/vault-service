package de.trustylynx.domain

import kotlinx.serialization.Serializable

@Serializable
data class KdfParams(
    val alg: String,
    val m: Int,
    val t: Int,
    val p: Int,
    val len: Int,
) {
    companion object {
        val DEFAULT = KdfParams(alg = "argon2id", m = 65536, t = 3, p = 1, len = 32)
    }
}
