package de.trustylynx.persistence

import de.trustylynx.common.withConnection
import de.trustylynx.domain.StoredHead
import de.trustylynx.domain.StoredItem
import de.trustylynx.domain.StoredSecret
import javax.sql.DataSource

interface ItemRepository {
    /** Aktuelle Revision des Eintrags, oder null, wenn es ihn nicht gibt. */
    suspend fun currentRev(userId: String, itemId: String): Int?

    /** Legt einen neuen Eintrag an (rev 1). Gibt es ihn schon → false, es wird nichts überschrieben. */
    suspend fun insert(userId: String, item: StoredItem): Boolean

    /**
     * Überschreibt den Eintrag nur, wenn er gerade noch auf [previousRev] steht (atomar) → true.
     * Hat ihn inzwischen jemand anderes geändert oder gelöscht → false.
     */
    suspend fun update(userId: String, item: StoredItem, previousRev: Int): Boolean

    /** Köpfe aller Einträge des Nutzers (ohne Geheimnisse), sortiert nach itemId. Neuer Tresor → leere Liste. */
    suspend fun listHeads(userId: String): List<StoredHead>

    /** Geheimnis und Revision eines Eintrags, oder null, wenn es ihn (für diesen Nutzer) nicht gibt. */
    suspend fun findSecret(userId: String, itemId: String): StoredSecret?

    /** Löscht den Eintrag des Nutzers → true. Gibt es ihn nicht (mehr) → false. */
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

    // user_id in der Bedingung: Ein Nutzer kann nie den Eintrag eines anderen löschen, auch nicht mit dessen itemId.
    override suspend fun delete(userId: String, itemId: String): Boolean = dataSource.withConnection { connection ->
        connection.prepareStatement("DELETE FROM items WHERE user_id = ? AND item_id = ?").use { statement ->
            statement.setString(1, userId)
            statement.setString(2, itemId)
            statement.executeUpdate() == 1
        }
    }
}
