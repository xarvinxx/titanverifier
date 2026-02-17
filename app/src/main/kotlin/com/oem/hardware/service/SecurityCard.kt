package com.oem.hardware.service

/**
 * A security card for the audit UI.
 * @param name Display name (e.g. "Serial Number")
 * @param javaValue Value from Build.* (Java side)
 * @param nativeValue Value from __system_property_get (Native side), null if not compared
 * @param status Green = consistent/unremarkable, Red = deviation (e.g. hook indicator)
 */
data class SecurityCard(
    val name: String,
    val javaValue: String,
    val nativeValue: String?,
    val status: CardStatus
)

enum class CardStatus {
    OK,               // Green
    ALERT,            // Red (e.g. Serial Java ≠ Native)
    IDENTITY_MISMATCH // Widevine OK but Serial spoofed
}
