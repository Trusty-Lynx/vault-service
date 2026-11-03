package de.trustylynx.security

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// test vector V3 from the docs
class VerifierHasherTest {

    @Test
    fun `testvektor V3 ergibt den vault_verifier aus dem Handbuch`() {
        assertContentEquals(VAULT_VERIFIER, VerifierHasher.hash(H_VAULT, SALT_S_VAULT))
    }

    @Test
    fun `matches erkennt richtigen und falschen Verifier`() {
        assertTrue(VerifierHasher.matches(H_VAULT, SALT_S_VAULT, VAULT_VERIFIER))

        val wrongH = H_VAULT.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(VerifierHasher.matches(wrongH, SALT_S_VAULT, VAULT_VERIFIER))
    }

    private companion object {
        val H_VAULT = hex("07ba20d3aef456943970559dd7f3cb17d6fc3a769c5f4e60e84fc4cabd63031d")
        val SALT_S_VAULT = hex("ea348db1ebd35c74053d7d589034f28f")
        val VAULT_VERIFIER = hex("cba943583a06397eacb8434b595bee1ea6b1167283ed2f86e1854f2e9e5985f5")

        fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
