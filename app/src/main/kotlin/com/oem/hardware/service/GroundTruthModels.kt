package com.oem.hardware.service

/**
 * A single row in the Ground-Truth audit UI (Legacy single-value).
 */
data class AuditRow(
    val label: String,
    val value: String,
    val isCritical: Boolean = false,
    val forceRed: Boolean? = null
)

/** Layered Identity Analysis: Status per parameter. */
enum class LayeredStatus {
    /** Java != Native (both present) → Red. */
    INCONSISTENT,
    /** Java == Native != Root → Spoofing detected, Green. */
    SPOOFED,
    /** All layers consistent or only one layer. */
    CONSISTENT,
    /** No value in any layer (after root fallback). */
    MISSING,
    /** No comparison possible (e.g. only one layer). */
    N_A
}

/**
 * A row for the Layered Identity matrix: Java | Native | Root.
 * @param status INCONSISTENT (Red), SPOOFED (Green), CONSISTENT, MISSING, N_A
 */
data class LayeredAuditRow(
    val label: String,
    val javaValue: String,
    val nativeValue: String,
    val rootValue: String,
    val isCritical: Boolean = false,
    val status: LayeredStatus = LayeredStatus.N_A
)

/**
 * A category (expandable) with multiple rows.
 */
data class AuditSection(
    val title: String,
    val rows: List<AuditRow>
)

/** Category with Layered rows (comparison matrix). */
data class LayeredAuditSection(
    val title: String,
    val rows: List<LayeredAuditRow>
)
