package de.trustylynx.repositories

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.flywaydb.core.Flyway
import java.sql.Connection
import java.sql.SQLException
import javax.sql.DataSource

private const val POOL_NAME = "vault-db"
private const val MAX_POOL_SIZE = 10

class DbConfig(
    val url: String,
    val user: String,
    val password: String,
)

fun createDataSource(config: DbConfig): HikariDataSource = HikariDataSource(
    HikariConfig().apply {
        poolName = POOL_NAME
        jdbcUrl = config.url
        username = config.user
        password = config.password
        maximumPoolSize = MAX_POOL_SIZE
        connectionTimeout = 5_000
    },
)

// The server DB already had vaults and vault_sessions from before Flyway. baselineOnMigrate marks such a DB
// as V1 once, after that only newer migrations run. An empty DB just gets V1, V2, ...
fun migrateDatabase(dataSource: DataSource) {
    Flyway.configure()
        .dataSource(dataSource)
        .baselineOnMigrate(true)
        .baselineVersion("1")
        .load()
        .migrate()
}

suspend fun DataSource.isReachable(): Boolean =
    try {
        withConnection { it.isValid(2) }
    } catch (_: SQLException) {
        false
    }

// JDBC blocks, so it runs on the IO dispatcher
suspend fun <T> DataSource.withConnection(block: (Connection) -> T): T = withContext(Dispatchers.IO) {
    connection.use(block)
}

suspend fun <T> DataSource.withTransaction(block: (Connection) -> T): T = withConnection { connection ->
    connection.autoCommit = false
    try {
        val result = block(connection)
        connection.commit()
        result
    } catch (e: Throwable) {
        connection.rollback()
        throw e
    } finally {
        connection.autoCommit = true
    }
}
