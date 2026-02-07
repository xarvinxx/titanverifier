package com.titan.verifier.xposed

import de.robv.android.xposed.XposedBridge
import java.io.File

/**
 * Project Titan - Bridge Reader für LSPosed/Xposed Hooks
 * 
 * Liest die Spoofing-Werte aus der gemeinsamen Bridge-Datei
 * /data/local/tmp/.titan_identity (Key=Value Format)
 * 
 * Diese Klasse muss exakt dieselbe Datei parsen wie das Zygisk-Modul,
 * um Konsistenz zwischen Native und Java Hooks zu gewährleisten.
 */
object TitanBridgeReader {
    
    private const val TAG = "TitanBridge"
    
    // Bridge-Pfade (Phase 6.0 - Multi-Path für LSPosed Zugriff)
    // LSPosed läuft mit App-Rechten, daher App-Datenordner priorisieren!
    private val BRIDGE_PATHS = arrayOf(
        // App-eigene Datenordner (LSPosed kann diese lesen!)
        "/data/data/com.titan.verifier/files/.titan_identity",
        "/data/data/com.titan.verifier/files/titan_identity",
        "/data/user/0/com.titan.verifier/files/.titan_identity",
        
        // TikTok Datenordner (falls dort gespiegelt)
        "/data/data/com.zhiliaoapp.musically/files/.titan_identity",
        "/data/data/com.ss.android.ugc.trill/files/.titan_identity",
        
        // World-readable Pfade
        "/sdcard/.titan_identity",
        "/storage/emulated/0/.titan_identity",
        "/sdcard/Android/data/com.titan.verifier/files/.titan_identity",
        
        // Root-only (funktioniert nur wenn Zygisk aktiv)
        "/data/adb/modules/titan_verifier/titan_identity",
        "/data/local/tmp/.titan_identity"
    )
    
    // Gecachte Werte
    private var cachedValues: Map<String, String>? = null
    private var lastLoadTime: Long = 0
    private const val CACHE_DURATION_MS = 5000L  // 5 Sekunden Cache
    
    /**
     * Lädt die Bridge-Werte aus der Datei.
     * Cached für Performance.
     */
    @Synchronized
    fun loadBridgeValues(): Map<String, String> {
        val now = System.currentTimeMillis()
        
        // Cache noch gültig?
        cachedValues?.let { cached ->
            if (now - lastLoadTime < CACHE_DURATION_MS) {
                return cached
            }
        }
        
        // Versuche alle Pfade
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
    
    /**
     * Parst eine Key=Value Datei.
     */
    private fun parseKeyValueFile(file: File): Map<String, String> {
        val values = mutableMapOf<String, String>()
        
        file.readLines().forEach { line ->
            val trimmed = line.trim()
            
            // Leere Zeilen und Kommentare überspringen
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
    
    // === Getter für spezifische Werte ===
    
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
    
    /**
     * Prüft ob die Bridge geladen werden kann.
     */
    fun isBridgeAvailable(): Boolean {
        return loadBridgeValues().isNotEmpty()
    }
    
    /**
     * Erzwingt Neuladen beim nächsten Zugriff.
     */
    fun invalidateCache() {
        cachedValues = null
        lastLoadTime = 0
    }
    
    /**
     * Debug-Logging via XposedBridge.
     */
    private fun log(msg: String) {
        try {
            XposedBridge.log("[$TAG] $msg")
        } catch (_: Throwable) {
            // Xposed nicht verfügbar (z.B. bei Unit-Tests)
        }
    }
}
