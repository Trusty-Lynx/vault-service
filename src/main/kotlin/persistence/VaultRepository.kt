package de.trustylynx.persistence

import de.trustylynx.common.AlreadyExists
import de.trustylynx.common.AppJson
import de.trustylynx.common.Caller
import de.trustylynx.common.withConnection
import de.trustylynx.common.withTransaction
import de.trustylynx.domain.KdfParams
import de.trustylynx.domain.Vault
import de.trustylynx.domain.VaultSession
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.SQLException
import java.sql.Timestamp
import java.time.Instant
import javax.sql.DataSource

interface VaultRepository {
    suspend fun exists(userId: String): Boolean

    /** Der Tresor des Nutzers, oder null, wenn es (noch) keinen gibt. */
    suspend fun find(userId: String): Vault?

    /** Speichert Tresor und ersten Tresor-Token zusammen. Gibt es den Tresor schon → [de.trustylynx.common.AlreadyExists]. */
    suspend fun create(vault: Vault, session: VaultSession)

    /** Speichert einen weiteren Tresor-Token (nach dem Entsperren). */
    suspend fun createSession(session: VaultSession)

    /**
     * Prüft und verlängert einen Tresor-Token in einem Schritt (atomar):
     * Passt [tokenHash] zu userId, deviceId und sessionId von [caller] und ist er nach [now] noch gültig,
     * wird `expires_at` auf [newExpiresAt] gesetzt → true. Sonst bleibt alles, wie es ist → false.
     */
    suspend fun touchSession(tokenHash: ByteArray, caller: Caller, now: Instant, newExpiresAt: Instant): Boolean

    /** Löscht einen Tresor-Token, wenn er zu [caller] gehört und nach [now] noch gültig ist → true. Sonst false. */
    suspend fun deleteSession(tokenHash: ByteArray, caller: Caller, now: Instant): Boolean

    /** Räumt abgelaufene Tresor-Tokens des Nutzers weg, damit `vault_sessions` nicht endlos wächst. */
    suspend fun deleteExpiredSessions(userId: String, now: Instant)
}

class PostgresVaultRepository(private val dataSource: DataSource) : VaultRepository {

    override suspend fun exists(userId: String): Boolean = dataSource.withConnection { connection ->
        connection.prepareStatement("SELECT 1 FROM vaults WHERE user_id = ?").use { statement ->
            statement.setString(1, userId)
            statement.executeQuery().use { it.next() }
        }
    }

    override suspend fun find(userId: String): Vault? = dataSource.withConnection { connection ->
        connection.prepareStatement(
            """
            SELECT salt_vault, kdf_vault, salt_s_vault, vault_verifier, wdek_c2
            FROM vaults WHERE user_id = ?
            """.trimIndent(),
        ).use { statement ->
            statement.setString(1, userId)
            statement.executeQuery().use { row ->
                if (!row.next()) return@use null
                Vault(
                    userId = userId,
                    saltVault = row.getBytes("salt_vault"),
                    kdf = AppJson.decodeFromString(KdfParams.serializer(), row.getString("kdf_vault")),
                    saltSVault = row.getBytes("salt_s_vault"),
                    vaultVerifier = row.getBytes("vault_verifier"),
                    wdekC2 = row.getBytes("wdek_c2"),
                )
            }
        }
    }

    override suspend fun create(vault: Vault, session: VaultSession) {
        try {
            dataSource.withTransaction { connection ->
                connection.prepareStatement(
                    """
                    INSERT INTO vaults (user_id, salt_vault, kdf_vault, salt_s_vault, vault_verifier, wdek_c2)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """.trimIndent(),
                ).use { statement ->
                    statement.setString(1, vault.userId)
                    statement.setBytes(2, vault.saltVault)
                    statement.setString(3, AppJson.encodeToString(KdfParams.serializer(), vault.kdf))
                    statement.setBytes(4, vault.saltSVault)
                    statement.setBytes(5, vault.vaultVerifier)
                    statement.setBytes(6, vault.wdekC2)
                    statement.executeUpdate()
                }
                insertSession(connection, session)
            }
        } catch (e: SQLException) {
            // Zwei Anfragen gleichzeitig: exists() war bei beiden false, der Primary Key fängt die zweite ab.
            if (e.sqlState == UNIQUE_VIOLATION) throw AlreadyExists()
            throw e
        }
    }

    override suspend fun createSession(session: VaultSession) = dataSource.withConnection { connection ->
        insertSession(connection, session)
    }

    // Prüfen und Verlängern in einem UPDATE: kein Zeitfenster zwischen "ist gültig" und "verlängern".
    override suspend fun touchSession(tokenHash: ByteArray, caller: Caller, now: Instant, newExpiresAt: Instant): Boolean =
        dataSource.withConnection { connection ->
            connection.prepareStatement(
                """
                UPDATE vault_sessions SET expires_at = ?
                WHERE token_hash = ? AND user_id = ? AND device_id = ? AND session_id = ? AND expires_at > ?
                """.trimIndent(),
            ).use { statement ->
                statement.setTimestamp(1, Timestamp.from(newExpiresAt))
                bindSessionMatch(statement, firstIndex = 2, tokenHash, caller, now)
                statement.executeUpdate() == 1
            }
        }

    override suspend fun deleteSession(tokenHash: ByteArray, caller: Caller, now: Instant): Boolean =
        dataSource.withConnection { connection ->
            connection.prepareStatement(
                """
                DELETE FROM vault_sessions
                WHERE token_hash = ? AND user_id = ? AND device_id = ? AND session_id = ? AND expires_at > ?
                """.trimIndent(),
            ).use { statement ->
                bindSessionMatch(statement, firstIndex = 1, tokenHash, caller, now)
                statement.executeUpdate() == 1
            }
        }

    override suspend fun deleteExpiredSessions(userId: String, now: Instant) {
        dataSource.withConnection { connection ->
            connection.prepareStatement("DELETE FROM vault_sessions WHERE user_id = ? AND expires_at <= ?").use { statement ->
                statement.setString(1, userId)
                statement.setTimestamp(2, Timestamp.from(now))
                statement.executeUpdate()
            }
        }
    }

    /** Setzt die fünf Platzhalter von `token_hash = ? AND user_id = ? AND device_id = ? AND session_id = ? AND expires_at > ?`. */
    private fun bindSessionMatch(statement: PreparedStatement, firstIndex: Int, tokenHash: ByteArray, caller: Caller, now: Instant) {
        statement.setBytes(firstIndex, tokenHash)
        statement.setString(firstIndex + 1, caller.userId)
        statement.setString(firstIndex + 2, caller.deviceId)
        statement.setString(firstIndex + 3, caller.sessionId)
        statement.setTimestamp(firstIndex + 4, Timestamp.from(now))
    }

    private fun insertSession(connection: Connection, session: VaultSession) {
        connection.prepareStatement(
            """
            INSERT INTO vault_sessions (token_hash, user_id, device_id, session_id, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """.trimIndent(),
        ).use { statement ->
            statement.setBytes(1, session.tokenHash)
            statement.setString(2, session.userId)
            statement.setString(3, session.deviceId)
            statement.setString(4, session.sessionId)
            statement.setTimestamp(5, Timestamp.from(session.expiresAt))
            statement.executeUpdate()
        }
    }

    private companion object {
        const val UNIQUE_VIOLATION = "23505"
    }
}
