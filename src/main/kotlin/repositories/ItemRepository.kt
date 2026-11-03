package de.trustylynx.repositories

import de.trustylynx.models.StoredHead
import de.trustylynx.models.StoredItem
import de.trustylynx.models.StoredSecret
import javax.sql.DataSource

interface ItemRepository {
    suspend fun currentRev(userId: String, itemId: String): Int?

    // false if it already exists, nothing gets overwritten
    suspend fun insert(userId: String, item: StoredItem): Boolean

    // false if someone else changed or deleted it in the meantime
    suspend fun update(userId: String, item: StoredItem, previousRev: Int): Boolean

    suspend fun listHeads(userId: String): List<StoredHead>

    suspend fun findSecret(userId: String, itemId: String): StoredSecret?

    suspend fun delete(userId: String, itemId: String): Boolean
}

class PostgresItemRepository(private val dataSource: DataSource) : ItemRepository {

    override suspend fun currentRev(userId: String, itemId: String): Int? = dataSource.withConnection { connection ->
        connection.prepareStatement("SELECT rev FROM items WHERE user_id = ? AND item_id = ?").use { statement ->
            statement.setString(1, userId)
            statement.setString(2, itemId)
            statement.executeQuery().use { row -> if (row.next()) row.getInt("rev") else null }
        }
    }

    // ON CONFLICT DO NOTHING instead of an error: if two requests create the same item, one wins and the other gets 409
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

    // "AND rev = ?" turns the UPDATE into the check: if the rev changed in the meantime, no row matches
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

    // secret_c2 is left out on purpose, passwords only come one at a time through GET /items/secret
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

    // user_id in the condition, so nobody can delete someone else's item, not even with its itemId
    override suspend fun delete(userId: String, itemId: String): Boolean = dataSource.withConnection { connection ->
        connection.prepareStatement("DELETE FROM items WHERE user_id = ? AND item_id = ?").use { statement ->
            statement.setString(1, userId)
            statement.setString(2, itemId)
            statement.executeUpdate() == 1
        }
    }
}
