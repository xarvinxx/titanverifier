package com.titan.verifier

/**
 * Native Identity Sync: Speichert GSF-ID und Android-ID im C++-Speicher,
 * sodass beide Ebenen (Java/Kotlin und Native) denselben Stand haben.
 * Wird von AuditEngine aufgerufen, sobald Identitätsdaten vorliegen.
 */
object NativeEngine {

    init {
        System.loadLibrary("native-lib")
    }

    /**
     * Synchronisiert GSF-ID und Android-ID in die Native-Ebene.
     * Thread-sicher; leere Strings werden als gültige Werte übernommen.
     */
    external fun syncIdentity(gsfId: String, androidId: String)

    /** Native-Backdoor: IMEI in C++ Hook-Memory setzen (bei Kernel-Block). */
    external fun setFakeImei(imei: String)

    /** Native-Backdoor: IMEI aus C++ Hook-Memory lesen. */
    external fun getNativeImei(): String
}
