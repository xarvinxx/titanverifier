package com.titan.verifier

/**
 * Eine Security-Card für die Audit-UI.
 * @param name Anzeigename (z. B. "Serial Number")
 * @param javaValue Wert von Build.* (Java-Seite)
 * @param nativeValue Wert von __system_property_get (Native-Seite), null wenn nicht verglichen
 * @param status Grün = konsistent/unauffällig, Rot = Abweichung (z. B. Hook-Indikator)
 */
data class SecurityCard(
    val name: String,
    val javaValue: String,
    val nativeValue: String?,
    val status: CardStatus
)

enum class CardStatus {
    OK,    // Grün
    ALERT  // Rot (z. B. Serial Java ≠ Native)
}
