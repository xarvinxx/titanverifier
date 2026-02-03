package com.titan.verifier

/**
 * Eine Zeile in der Ground-Truth-Audit-UI (Legacy single-value).
 */
data class AuditRow(
    val label: String,
    val value: String,
    val isCritical: Boolean = false,
    val forceRed: Boolean? = null
)

/** Layered Identity Analysis: Status pro Parameter. */
enum class LayeredStatus {
    /** Java != Native (beide vorhanden) → Rot. */
    INCONSISTENT,
    /** Java == Native != Root → Spoofing erkannt, Grün. */
    SPOOFED,
    /** Alle Schichten übereinstimmend oder nur eine Schicht. */
    CONSISTENT,
    /** Kein Wert in keiner Schicht (nach Root-Fallback). */
    MISSING,
    /** Kein Vergleich möglich (z. B. nur eine Schicht). */
    N_A
}

/**
 * Eine Zeile für die Layered Identity Matrix: Java | Native | Root.
 * @param status INCONSISTENT (Rot), SPOOFED (Grün), CONSISTENT, MISSING, N_A
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
 * Eine Kategorie (expandierbar) mit mehreren Zeilen.
 */
data class AuditSection(
    val title: String,
    val rows: List<AuditRow>
)

/** Kategorie mit Layered-Zeilen (Vergleichsmatrix). */
data class LayeredAuditSection(
    val title: String,
    val rows: List<LayeredAuditRow>
)
