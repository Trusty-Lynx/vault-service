package de.trustylynx.repositories

import de.trustylynx.models.AlreadyExists
import de.trustylynx.models.Caller
import de.trustylynx.models.KdfParams
import de.trustylynx.models.Vault
import de.trustylynx.models.VaultSession
import de.trustylynx.plugins.AppJson
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.SQLException
import java.sql.Timestamp
import java.time.Instant
import javax.sql.DataSource

private const val UNIQUE_VIOLATION = "23505"

interface VaultRepository {
    suspend fun exists(userId: String): Boolean

    suspend fun find(userId: String): Vault?

    // vault and first vault token in one transaction
    suspend fun create(vault: Vault, session: VaultSession)

    suspend fun createSession(session: VaultSession)

    // false if the token doesn't belong to the caller or has expired, then nothing changes
    suspend fun touchSession(tokenHash: ByteArray, caller: Caller, now: Instant, newExpiresAt: Instant): Boolean

    suspend fun deleteSession(tokenHash: ByteArray, caller: Caller, now: Instant): Boolean

    // so vault_sessions doesn't grow forever
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
            // two requests at the same time: exists() was false for both, the primary key stops the second one
            if (e.sqlState == UNIQUE_VIOLATION) throw AlreadyExists()
            throw e
        }
    }

    override suspend fun createSession(session: VaultSession) = dataSource.withConnection { connection ->
        insertSession(connection, session)
    }

    // check and extend in one UPDATE, so there's no gap between "is valid" and "extend"
    override suspend fun touchSession(tokenHash: ByteArray, caller: Caller, now: Instant, newExpiresAt: Instant): Boolean =
        dataSource.withConnection { connection ->
            connection.prepareStatement(
                """
                UPDATE vault_sessions SET expires_at = ?
                WHERE token_hash = ? AND user_id = ? AND session_id = ? AND expires_at > ?
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
                WHERE token_hash = ? AND user_id = ? AND session_id = ? AND expires_at > ?
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

    // fills token_hash = ? AND user_id = ? AND session_id = ? AND expires_at > ?
    private fun bindSessionMatch(statement: PreparedStatement, firstIndex: Int, tokenHash: ByteArray, caller: Caller, now: Instant) {
        statement.setBytes(firstIndex, tokenHash)
        statement.setString(firstIndex + 1, caller.userId)
        statement.setString(firstIndex + 2, caller.sessionId)
        statement.setTimestamp(firstIndex + 3, Timestamp.from(now))
    }

    private fun insertSession(connection: Connection, session: VaultSession) {
        connection.prepareStatement(
            """
            INSERT INTO vault_sessions (token_hash, user_id, session_id, expires_at)
            VALUES (?, ?, ?, ?)
            """.trimIndent(),
        ).use { statement ->
            statement.setBytes(1, session.tokenHash)
            statement.setString(2, session.userId)
            statement.setString(3, session.sessionId)
            statement.setTimestamp(4, Timestamp.from(session.expiresAt))
            statement.executeUpdate()
        }
    }
}
