package de.trustylynx.common

private val isDev: Boolean =
    System.getProperty("io.ktor.development")?.toBoolean() == true

/** Pflichtwert, überall. */
fun env(name: String): String =
    System.getenv(name)?.takeIf { it.isNotBlank() }
        ?: error("Missing required environment variable $name")

/** Optionaler Wert mit Default, überall (z. B. PORT, LOG_LEVEL). */
fun env(name: String, default: String): String =
    System.getenv(name)?.takeIf { it.isNotBlank() } ?: default

/** Pflichtwert in Prod, Default nur im Dev-Modus (z. B. DB_URL, Secrets). */
fun envOrDev(name: String, devDefault: String): String =
    System.getenv(name)?.takeIf { it.isNotBlank() }
        ?: devDefault.takeIf { isDev }
        ?: error("Missing required environment variable $name")
