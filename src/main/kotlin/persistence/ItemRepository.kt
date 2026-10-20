package de.trustylynx.persistence

import de.trustylynx.domain.StoredItem

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
}
