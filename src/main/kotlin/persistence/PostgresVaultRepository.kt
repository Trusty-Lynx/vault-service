package de.trustylynx.persistence

import de.trustylynx.common.AlreadyExists
import de.trustylynx.common.AppJson
import de.trustylynx.common.withConnection
import de.trustylynx.common.withTransaction
import de.trustylynx.domain.KdfParams
import de.trustylynx.domain.Vault
import de.trustylynx.domain.VaultSession
import java.sql.Connection
import java.sql.SQLException
import java.sql.Timestamp
import javax.sql.DataSource

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
