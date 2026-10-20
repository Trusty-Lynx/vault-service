package de.trustylynx.persistence

import de.trustylynx.common.withConnection
import de.trustylynx.domain.StoredHead
import de.trustylynx.domain.StoredItem
import de.trustylynx.domain.StoredSecret
import javax.sql.DataSource

class PostgresItemRepository(private val dataSource: DataSource) : ItemRepository {

    override suspend fun currentRev(userId: String, itemId: String): Int? = dataSource.withConnection { connection ->
        connection.prepareStatement("SELECT rev FROM items WHERE user_id = ? AND item_id = ?").use { statement ->
            statement.setString(1, userId)
            statement.setString(2, itemId)
            statement.executeQuery().use { row -> if (row.next()) row.getInt("rev") else null }
        }
    }

    // ON CONFLICT DO NOTHING statt Fehler: Zwei gleichzeitige "neu anlegen" → nur einer gewinnt, der andere bekommt 409.
    override suspend fun insert(userId: String, item: StoredItem): Boolean = dataSource.withConnection { connection ->
        connection.prepareStatement(
            """
            INSERT INTO items (user_id, item_id, rev, head_c2, secret_c2)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (user_id, item_id) DO NOTHING
            """.trimIndent(),
        ).use { statement ->
            statement.setString(1, userId)
            statement.setString(2, item.itemId)
            statement.setInt(3, item.rev)
            statement.setBytes(4, item.headC2)
            statement.setBytes(5, item.secretC2)
            statement.executeUpdate() == 1
        }
    }

    // "AND rev = ?" macht das UPDATE zur Prüfung: Hat sich die Revision inzwischen geändert, trifft es keine Zeile.
    override suspend fun update(userId: String, item: StoredItem, previousRev: Int): Boolean = dataSource.withConnection { connection ->
        connection.prepareStatement(
            """
            UPDATE items SET rev = ?, head_c2 = ?, secret_c2 = ?
            WHERE user_id = ? AND item_id = ? AND rev = ?
            """.trimIndent(),
        ).use { statement ->
            statement.setInt(1, item.rev)
            statement.setBytes(2, item.headC2)
            statement.setBytes(3, item.secretC2)
            statement.setString(4, userId)
            statement.setString(5, item.itemId)
            statement.setInt(6, previousRev)
            statement.executeUpdate() == 1
        }
    }

    // secret_c2 wird hier absichtlich nicht gelesen: Passwörter gibt es nur einzeln über GET /items/secret.
    override suspend fun listHeads(userId: String): List<StoredHead> = dataSource.withConnection { connection ->
        connection.prepareStatement("SELECT item_id, rev, head_c2 FROM items WHERE user_id = ? ORDER BY item_id").use { statement ->
            statement.setString(1, userId)
            statement.executeQuery().use { row ->
                buildList {
                    while (row.next()) add(StoredHead(row.getString("item_id"), row.getInt("rev"), row.getBytes("head_c2")))
                }
            }
        }
    }

    override suspend fun findSecret(userId: String, itemId: String): StoredSecret? = dataSource.withConnection { connection ->
        connection.prepareStatement("SELECT rev, secret_c2 FROM items WHERE user_id = ? AND item_id = ?").use { statement ->
            statement.setString(1, userId)
            statement.setString(2, itemId)
            statement.executeQuery().use { row ->
                if (row.next()) StoredSecret(row.getInt("rev"), row.getBytes("secret_c2")) else null
            }
        }
    }
}
