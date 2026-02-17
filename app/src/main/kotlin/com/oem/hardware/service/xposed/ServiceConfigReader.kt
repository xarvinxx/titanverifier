package com.oem.hardware.service.xposed

import de.robv.android.xposed.XposedBridge
import java.io.File

/**
 * Bridge reader for LSPosed/Xposed hooks.
 * Reads spoofing values from the shared config file (key=value format).
 * Must parse the same file as the Zygisk module for consistency.
 */
object ServiceConfigReader {

    private const val TAG = "HwBridge"

    private fun getBridgePaths(): Array<String> {
        val paths = mutableListOf<String>()

        try {
            val atClass = Class.forName("android.app.ActivityThread")
            val currentPkg = atClass.getMethod("currentPackageName").invoke(null) as? String
            if (!currentPkg.isNullOrEmpty()) {
                val selfDataDir = "/data/data/$currentPkg/files"
                paths.add("$selfDataDir/.hw_config")
                paths.add("$selfDataDir/.hw_config")
            }
        } catch (_: Throwable) {}

        val knownApps = arrayOf(
            "com.oem.hardware.service",
            "tw.reh.deviceid",
            "com.androidfung.drminfo",
            "com.zhiliaoapp.musically",
            "com.ss.android.ugc.trill"
        )
        for (app in knownApps) {
            paths.add("/data/data/$app/files/.hw_config")
        }
        paths.add("/data/user/0/com.oem.hardware.service/files/.hw_config")

        paths.add("/sdcard/.hw_config")
        paths.add("/storage/emulated/0/.hw_config")
        paths.add("/sdcard/Android/data/com.oem.hardware.service/files/.hw_config")

        paths.add("/data/adb/modules/hw_overlay/.hw_config")
        paths.add("/data/local/tmp/.hw_config")

        return paths.toTypedArray()
    }

    private val BRIDGE_PATHS: Array<String> get() = getBridgePaths()

    private var cachedValues: Map<String, String>? = null
    private var lastLoadTime: Long = 0
    private const val CACHE_DURATION_MS = 5000L

    @Synchronized
    fun loadBridgeValues(): Map<String, String> {
        val now = System.currentTimeMillis()

        cachedValues?.let { cached ->
            if (now - lastLoadTime < CACHE_DURATION_MS) {
                return cached
            }
        }

        for (path in BRIDGE_PATHS) {
            try {
                val file = File(path)
                if (file.exists() && file.canRead()) {
                    val values = parseKeyValueFile(file)
                    if (values.isNotEmpty()) {
                        cachedValues = values
                        lastLoadTime = now
                        log("Bridge loaded from $path (${values.size} values)")
                        return values
                    }
                }
            } catch (e: Exception) {
                log("Error reading $path: ${e.message}")
            }
        }

        log("Failed to load bridge from any path!")
        return emptyMap()
    }

    private fun parseKeyValueFile(file: File): Map<String, String> {
        val values = mutableMapOf<String, String>()

        file.readLines().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
            val eqIndex = trimmed.indexOf('=')
            if (eqIndex > 0) {
                val key = trimmed.substring(0, eqIndex).trim().lowercase()
                val value = trimmed.substring(eqIndex + 1).trim()
                if (value.isNotEmpty()) {
                    values[key] = value
                }
            }
        }

        return values
    }

    fun getSerial(): String? = loadBridgeValues()["serial"]

    fun getBootSerial(): String? = loadBridgeValues()["boot_serial"]

    fun getImei1(): String? = loadBridgeValues()["imei1"] ?: loadBridgeValues()["imei"]

    fun getImei2(): String? = loadBridgeValues()["imei2"]

    fun getGsfId(): String? = loadBridgeValues()["gsf_id"] ?: loadBridgeValues()["gsfid"]

    fun getAndroidId(): String? = loadBridgeValues()["android_id"]

    fun getWifiMac(): String? = loadBridgeValues()["wifi_mac"] ?: loadBridgeValues()["mac_wlan0"]

    fun getWidevineId(): String? = loadBridgeValues()["widevine_id"]

    fun getImsi(): String? = loadBridgeValues()["imsi"]

    fun getSimSerial(): String? = loadBridgeValues()["sim_serial"] ?: loadBridgeValues()["iccid"]

    fun getOperatorName(): String? = loadBridgeValues()["operator_name"] ?: loadBridgeValues()["operator"]

    fun getPhoneNumber(): String? = loadBridgeValues()["phone_number"] ?: loadBridgeValues()["line1_number"]

    fun getSimOperator(): String? = loadBridgeValues()["sim_operator"] ?: loadBridgeValues()["mcc_mnc"]

    fun getSimOperatorName(): String? = loadBridgeValues()["sim_operator_name"]

    fun getVoicemailNumber(): String? = loadBridgeValues()["voicemail_number"]

    fun isBridgeAvailable(): Boolean {
        return loadBridgeValues().isNotEmpty()
    }

    fun invalidateCache() {
        cachedValues = null
        lastLoadTime = 0
    }

    private fun log(msg: String) {
        try {
            XposedBridge.log("[$TAG] $msg")
        } catch (_: Throwable) {}
    }
}
