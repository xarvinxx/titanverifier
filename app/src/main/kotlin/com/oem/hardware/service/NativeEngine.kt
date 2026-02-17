package com.oem.hardware.service

/**
 * Native Identity Sync: Stores GSF-ID and Android-ID in C++ memory
 * so Java/Kotlin and Native stay in sync.
 * Called by AuditEngine once identity data is available.
 */
object NativeEngine {

    init {
        System.loadLibrary("native-lib")
    }

    /**
     * Syncs GSF-ID and Android-ID to the native layer.
     * Thread-safe; empty strings are accepted as valid values.
     */
    external fun syncIdentity(gsfId: String, androidId: String)

    /** Native backdoor: set IMEI in C++ hook memory (when kernel blocks). */
    external fun setFakeImei(imei: String)

    /** Native backdoor: read IMEI from C++ hook memory. */
    external fun getNativeImei(): String
}
