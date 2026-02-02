package com.titan.verifier

/**
 * JNI-Bridge für Native Property-Abfrage (Audit).
 * Vergleicht Java Build.* mit __system_property_get (z. B. Serial).
 */
object AuditEngine {
    init {
        System.loadLibrary("native-lib")
    }

    /**
     * Liest System-Property nativ (z. B. ro.serialno, ro.boot.serialno).
     * @param key z. B. "SERIAL", "MODEL", "ID", "FINGERPRINT"
     * @return Wert der Property oder leerer String
     */
    external fun getNativeProperty(key: String): String
}
