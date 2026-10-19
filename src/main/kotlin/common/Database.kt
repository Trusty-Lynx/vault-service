package de.trustylynx.common

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.sql.Connection
import javax.sql.DataSource

class DbConfig(
    val url: String,
    val user: String,
    val password: String,
    val poolName: String,
    val maximumPoolSize: Int = 10,
) {
    override fun toString(): String = "DbConfig(url=$url, user=$user, poolName=$poolName)"
}

/** Connection-Pool. Muss beim Stoppen der Anwendung geschlossen werden. */
fun createDataSource(config: DbConfig): HikariDataSource = HikariDataSource(
    HikariConfig().apply {
        poolName = config.poolName
        jdbcUrl = config.url
        username = config.user
        password = config.password
        maximumPoolSize = config.maximumPoolSize
    },
)

/** Führt [block] mit einer Connection aus dem Pool auf dem IO-Dispatcher aus. */
suspend fun <T> DataSource.withConnection(block: (Connection) -> T): T = withContext(Dispatchers.IO) {
    connection.use(block)
}

/**
 * Wie [withConnection], aber alles in [block] läuft in einer Transaktion:
 * Entweder werden alle Änderungen gespeichert oder keine (z. B. Tresor + Tresor-Token).
 */
suspend fun <T> DataSource.withTransaction(block: (Connection) -> T): T = withConnection { connection ->
    connection.autoCommit = false
    try {
        block(connection).also { connection.commit() }
    } catch (e: Throwable) {
        connection.rollback()
        throw e
    } finally {
        connection.autoCommit = true
    }
}
