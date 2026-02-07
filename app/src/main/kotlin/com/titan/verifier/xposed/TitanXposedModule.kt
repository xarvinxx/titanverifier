package com.titan.verifier.xposed

import android.content.ContentResolver
import android.database.Cursor
import android.database.MatrixCursor
import android.hardware.input.InputManager
import android.media.MediaDrm
import android.net.Uri
import android.net.wifi.WifiInfo
import android.provider.Settings
import android.telephony.TelephonyManager
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.File
import java.io.FileInputStream
import java.net.NetworkInterface

/**
 * Project Titan - LSPosed Module (Phase 6.0 - Total Stealth)
 * 
 * EXTENDED SCOPE: Verifier, TikTok, GMS, Play Store
 * FULL COVERAGE: GSF, Widevine, MAC, All IDs
 */
class TitanXposedModule : IXposedHookLoadPackage {

    companion object {
        private const val TAG = "TITAN-TOTAL"
        
        // EXTENDED SCOPE - Alle relevanten Packages
        private val TARGET_PACKAGES = setOf(
            "com.titan.verifier",           // Unser Auditor
            "com.zhiliaoapp.musically",     // TikTok International
            "com.ss.android.ugc.trill",     // TikTok
            "com.google.android.gms",       // GMS (für GSF)
            "com.android.vending",          // Play Store
            "com.google.android.gsf",       // GSF Provider
            "android"                        // System Framework
        )
        
        private const val GSF_CONTENT_URI = "content://com.google.android.gsf.gservices"
        
        // MAC-Pfade die wir abfangen
        private val MAC_PATHS = setOf(
            "/sys/class/net/wlan0/address",
            "/sys/class/net/eth0/address",
            "/proc/net/arp"
        )
        
        // Lazy Bridge Cache
        @Volatile private var bridgeLoaded = false
        private var cachedGsfId: String? = null
        private var cachedAndroidId: String? = null
        private var cachedImei1: String? = null
        private var cachedImei2: String? = null
        private var cachedMac: String? = null
        private var cachedWidevine: String? = null
        private var cachedImsi: String? = null
        private var cachedSimSerial: String? = null
        private var cachedSerial: String? = null
        private var cachedOperator: String? = null
    }
    
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName !in TARGET_PACKAGES) return
        
        log("Phase 6.0 Total Stealth for: ${lpparam.packageName}")
        
        // Core Identity Hooks
        safeHook("TelephonyManager") { hookTelephonyManager() }
        safeHook("Settings.Secure") { hookSettingsSecure() }
        safeHook("SystemProperties") { hookSystemProperties(lpparam) }
        
        // GSF Total Coverage
        safeHook("GSF-ContentResolver") { hookGsfContentResolver() }
        safeHook("GSF-ContentProviderClient") { hookGsfContentProviderClient(lpparam) }
        safeHook("Gservices-Direct") { hookGservicesDirect(lpparam) }
        
        // MAC Total Coverage
        safeHook("WifiInfo") { hookWifiInfo() }
        safeHook("NetworkInterface") { hookNetworkInterface() }
        safeHook("FileInputStream-MAC") { hookFileInputStreamMac() }
        safeHook("File.readText-MAC") { hookFileReadTextMac(lpparam) }
        
        // Widevine Total Coverage
        safeHook("MediaDrm-Widevine") { hookMediaDrm() }
        
        // Stealth
        safeHook("InputManager") { hookInputManager() }
        
        log("Total Stealth hooks complete for ${lpparam.packageName}")
    }
    
    private fun ensureBridgeLoaded() {
        if (bridgeLoaded) return
        try {
            cachedGsfId = TitanBridgeReader.getGsfId()
            cachedAndroidId = TitanBridgeReader.getAndroidId()
            cachedImei1 = TitanBridgeReader.getImei1()
            cachedImei2 = TitanBridgeReader.getImei2()
            cachedMac = TitanBridgeReader.getWifiMac()
            cachedWidevine = TitanBridgeReader.getWidevineId()
            cachedImsi = TitanBridgeReader.getImsi()
            cachedSimSerial = TitanBridgeReader.getSimSerial()
            cachedSerial = TitanBridgeReader.getSerial()
            cachedOperator = TitanBridgeReader.getOperatorName()
            bridgeLoaded = true
            log("Bridge loaded: GSF=$cachedGsfId, MAC=$cachedMac, Widevine=$cachedWidevine")
        } catch (e: Throwable) {
            log("Bridge error: ${e.message}")
        }
    }
    
    private inline fun safeHook(name: String, block: () -> Unit) {
        try {
            block()
            log("Applied: $name")
        } catch (e: Throwable) {
            log("Failed: $name - ${e.message}")
        }
    }
    
    // =========================================================================
    // TelephonyManager
    // =========================================================================
    
    private fun hookTelephonyManager() {
        val tm = TelephonyManager::class.java
        
        XposedHelpers.findAndHookMethod(tm, "getImei", Int::class.javaPrimitiveType, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                ensureBridgeLoaded()
                val slot = param.args[0] as Int
                val v = if (slot == 0) cachedImei1 else cachedImei2
                v?.let { param.result = it; log("Spoofed IMEI($slot)") }
            }
        })
        
        XposedHelpers.findAndHookMethod(tm, "getImei", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                ensureBridgeLoaded()
                cachedImei1?.let { param.result = it; log("Spoofed IMEI()") }
            }
        })
        
        try {
            XposedHelpers.findAndHookMethod(tm, "getDeviceId", Int::class.javaPrimitiveType, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    val slot = param.args[0] as Int
                    (if (slot == 0) cachedImei1 else cachedImei2)?.let { param.result = it }
                }
            })
            XposedHelpers.findAndHookMethod(tm, "getDeviceId", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    cachedImei1?.let { param.result = it }
                }
            })
        } catch (_: Throwable) {}
        
        try {
            XposedHelpers.findAndHookMethod(tm, "getSubscriberId", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    cachedImsi?.let { param.result = it }
                }
            })
            XposedHelpers.findAndHookMethod(tm, "getSimSerialNumber", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    cachedSimSerial?.let { param.result = it }
                }
            })
            XposedHelpers.findAndHookMethod(tm, "getNetworkOperatorName", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    cachedOperator?.let { param.result = it }
                }
            })
        } catch (_: Throwable) {}
    }
    
    // =========================================================================
    // Settings.Secure (Android ID)
    // =========================================================================
    
    private fun hookSettingsSecure() {
        XposedHelpers.findAndHookMethod(
            Settings.Secure::class.java, "getString",
            ContentResolver::class.java, String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val name = param.args[1] as? String ?: return
                    if (name == Settings.Secure.ANDROID_ID) {
                        ensureBridgeLoaded()
                        cachedAndroidId?.let {
                            param.result = it
                            log("Spoofed ANDROID_ID -> $it")
                        }
                    }
                }
            }
        )
    }
    
    // =========================================================================
    // SystemProperties
    // =========================================================================
    
    private fun hookSystemProperties(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            val sp = XposedHelpers.findClass("android.os.SystemProperties", lpparam.classLoader)
            
            XposedHelpers.findAndHookMethod(sp, "get", String::class.java, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    handlePropertyGet(param.args[0] as? String, param)
                }
            })
            XposedHelpers.findAndHookMethod(sp, "get", String::class.java, String::class.java, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    handlePropertyGet(param.args[0] as? String, param)
                }
            })
        } catch (_: Throwable) {}
    }
    
    private fun handlePropertyGet(key: String?, param: XC_MethodHook.MethodHookParam) {
        if (key == null) return
        ensureBridgeLoaded()
        
        when {
            key.contains("gsf", ignoreCase = true) || key == "ro.com.google.gservices.gsf.id" -> {
                cachedGsfId?.let { param.result = it; log("Spoofed SystemProperties($key) -> $it") }
            }
            key == "ro.serialno" || key == "ro.boot.serialno" -> {
                cachedSerial?.let { param.result = it }
            }
        }
    }
    
    // =========================================================================
    // GSF Total Coverage - ContentResolver.query
    // =========================================================================
    
    private fun hookGsfContentResolver() {
        XposedHelpers.findAndHookMethod(
            ContentResolver::class.java, "query",
            Uri::class.java, Array<String>::class.java, String::class.java,
            Array<String>::class.java, String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val uri = param.args[0] as? Uri ?: return
                    val uriStr = uri.toString()
                    
                    if (uriStr.contains("gsf") || uriStr.contains("gservices")) {
                        ensureBridgeLoaded()
                        cachedGsfId?.let { gsfId ->
                            // MatrixCursor mit ALLEN GSF-relevanten Feldern
                            val cursor = MatrixCursor(arrayOf("name", "value"))
                            cursor.addRow(arrayOf("android_id", gsfId))
                            cursor.addRow(arrayOf("gsf_id", gsfId))
                            cursor.addRow(arrayOf("device_id", gsfId))
                            param.result = cursor
                            log("GSF MatrixCursor injected -> $gsfId")
                        }
                    }
                }
            }
        )
    }
    
    // =========================================================================
    // GSF Total Coverage - ContentProviderClient.query
    // =========================================================================
    
    private fun hookGsfContentProviderClient(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            val cpc = XposedHelpers.findClass("android.content.ContentProviderClient", lpparam.classLoader)
            
            XposedHelpers.findAndHookMethod(cpc, "query",
                Uri::class.java, Array<String>::class.java, String::class.java,
                Array<String>::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val uri = param.args[0] as? Uri ?: return
                        if (uri.toString().contains("gsf") || uri.toString().contains("gservices")) {
                            ensureBridgeLoaded()
                            cachedGsfId?.let { gsfId ->
                                val cursor = MatrixCursor(arrayOf("name", "value"))
                                cursor.addRow(arrayOf("android_id", gsfId))
                                param.result = cursor
                                log("GSF ContentProviderClient -> $gsfId")
                            }
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
    }
    
    // =========================================================================
    // GSF Total Coverage - Gservices.getString/getLong direkt
    // =========================================================================
    
    private fun hookGservicesDirect(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            val gs = XposedHelpers.findClass("com.google.android.gsf.Gservices", lpparam.classLoader)
            
            XposedHelpers.findAndHookMethod(gs, "getString",
                ContentResolver::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val key = param.args[1] as? String ?: return
                        if (key == "android_id" || key.contains("gsf", ignoreCase = true)) {
                            ensureBridgeLoaded()
                            cachedGsfId?.let { param.result = it; log("Gservices.getString($key) -> $it") }
                        }
                    }
                }
            )
            
            XposedHelpers.findAndHookMethod(gs, "getLong",
                ContentResolver::class.java, String::class.java, Long::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val key = param.args[1] as? String ?: return
                        if (key == "android_id" || key.contains("gsf", ignoreCase = true)) {
                            ensureBridgeLoaded()
                            cachedGsfId?.toLongOrNull()?.let { param.result = it; log("Gservices.getLong($key) -> $it") }
                        }
                    }
                }
            )
        } catch (_: Throwable) {
            log("Gservices class not found (expected outside GMS)")
        }
    }
    
    // =========================================================================
    // MAC Total Coverage - WifiInfo
    // =========================================================================
    
    private fun hookWifiInfo() {
        XposedHelpers.findAndHookMethod(WifiInfo::class.java, "getMacAddress", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                ensureBridgeLoaded()
                cachedMac?.let { param.result = it; log("WifiInfo.getMacAddress -> $it") }
            }
        })
    }
    
    // =========================================================================
    // MAC Total Coverage - NetworkInterface
    // =========================================================================
    
    private fun hookNetworkInterface() {
        XposedHelpers.findAndHookMethod(NetworkInterface::class.java, "getHardwareAddress", object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val ni = param.thisObject as? NetworkInterface ?: return
                val name = ni.name ?: return
                if (name != "wlan0" && name != "eth0") return
                
                ensureBridgeLoaded()
                cachedMac?.let { mac ->
                    parseMacToBytes(mac)?.let {
                        param.result = it
                        log("NetworkInterface($name).getHardwareAddress -> $mac")
                    }
                }
            }
        })
    }
    
    // =========================================================================
    // MAC Total Coverage - FileInputStream (für /sys/ Zugriffe)
    // =========================================================================
    
    private fun hookFileInputStreamMac() {
        // File constructor
        XposedHelpers.findAndHookConstructor(FileInputStream::class.java, File::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val file = param.args[0] as? File ?: return
                if (file.absolutePath in MAC_PATHS || (file.absolutePath.contains("/sys/class/net/") && file.absolutePath.endsWith("/address"))) {
                    ensureBridgeLoaded()
                    cachedMac?.let { mac ->
                        val tempFile = File.createTempFile("titan_", ".tmp")
                        tempFile.writeText("$mac\n")
                        tempFile.deleteOnExit()
                        param.args[0] = tempFile
                        log("FileInputStream(File) MAC redirect -> $mac")
                    }
                }
            }
        })
        
        // String path constructor
        XposedHelpers.findAndHookConstructor(FileInputStream::class.java, String::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                val path = param.args[0] as? String ?: return
                if (path in MAC_PATHS || (path.contains("/sys/class/net/") && path.endsWith("/address"))) {
                    ensureBridgeLoaded()
                    cachedMac?.let { mac ->
                        val tempFile = File.createTempFile("titan_", ".tmp")
                        tempFile.writeText("$mac\n")
                        tempFile.deleteOnExit()
                        param.args[0] = tempFile.absolutePath
                        log("FileInputStream(String) MAC redirect -> $mac")
                    }
                }
            }
        })
    }
    
    // =========================================================================
    // MAC Total Coverage - Kotlin File.readText
    // =========================================================================
    
    private fun hookFileReadTextMac(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "kotlin.io.FilesKt__FileReadWriteKt", lpparam.classLoader,
                "readText", File::class.java, java.nio.charset.Charset::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val file = param.args[0] as? File ?: return
                        if (file.absolutePath in MAC_PATHS) {
                            ensureBridgeLoaded()
                            cachedMac?.let {
                                param.result = "$it\n"
                                log("File.readText MAC -> $it")
                            }
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
    }
    
    // =========================================================================
    // Widevine Total Coverage - MediaDrm (Phase 7.8 Full Emulation)
    // =========================================================================
    
    private fun hookMediaDrm() {
        // Master Widevine ID (Phase 7.8 - Fixed Pixel 6 Identity)
        val MASTER_WIDEVINE_ID = "10179c6bcba352dbd5ce5c88fec8e098"
        // Phase 9.5: Konstruktor-Exception UNTERDRÜCKEN
        try {
            XposedHelpers.findAndHookConstructor(
                MediaDrm::class.java,
                java.util.UUID::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.throwable != null) {
                            log("MediaDrm constructor: SUPPRESSING ${param.throwable.javaClass.simpleName}")
                            param.throwable = null // Exception unterdrücken!
                        }
                    }
                }
            )
            log("MediaDrm constructor hook: Exception suppression ACTIVE")
        } catch (e: Throwable) {
            log("MediaDrm constructor hook failed: ${e.message}")
        }
        
        // getPropertyByteArray - MUSS im beforeHookedMethod greifen (vor Original!)
        XposedHelpers.findAndHookMethod(MediaDrm::class.java, "getPropertyByteArray", String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val prop = param.args[0] as? String ?: return
                    
                    if (prop == MediaDrm.PROPERTY_DEVICE_UNIQUE_ID || 
                        prop.equals("deviceUniqueId", ignoreCase = true)) {
                        
                        ensureBridgeLoaded()
                        val widevineHex = cachedWidevine ?: MASTER_WIDEVINE_ID
                        hexToBytes(widevineHex)?.let { bytes ->
                            param.result = bytes
                            log("MediaDrm.getPropertyByteArray($prop) -> ${bytes.size} bytes SPOOFED")
                        }
                    }
                }
            }
        )
        
        // getPropertyString
        XposedHelpers.findAndHookMethod(MediaDrm::class.java, "getPropertyString", String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val prop = param.args[0] as? String ?: return
                    if (prop.contains("device", ignoreCase = true) || prop.contains("unique", ignoreCase = true)) {
                        ensureBridgeLoaded()
                        param.result = cachedWidevine ?: MASTER_WIDEVINE_ID
                    }
                }
            }
        )
        
        // close() + release() - Fehler bei leerem DRM-Objekt unterdrücken
        try {
            XposedHelpers.findAndHookMethod(MediaDrm::class.java, "close",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.throwable != null) {
                            param.throwable = null
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
        
        try {
            XposedHelpers.findAndHookMethod(MediaDrm::class.java, "release",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.throwable != null) {
                            param.throwable = null
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
    }
    
    // =========================================================================
    // InputManager (Stealth) - Phase 9.5: Echte Mock-InputDevices via Reflection
    // =========================================================================
    
    private fun hookInputManager() {
        // getInputDeviceIds - Gib echte Pixel 6 Device-IDs zurück
        XposedHelpers.findAndHookMethod(InputManager::class.java, "getInputDeviceIds", object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                val result = param.result as? IntArray
                if (result == null || result.isEmpty()) {
                    param.result = intArrayOf(1, 2, 3)
                    log("InputManager.getInputDeviceIds() -> [1, 2, 3]")
                }
            }
        })
        
        // getInputDevice(id) - Echtes Mock-InputDevice via Reflection
        try {
            XposedHelpers.findAndHookMethod(InputManager::class.java, "getInputDevice", Int::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.result != null) return // Echtes Gerät existiert
                        
                        val id = param.args[0] as Int
                        try {
                            val mockDevice = createMockInputDevice(id)
                            if (mockDevice != null) {
                                param.result = mockDevice
                                log("InputManager.getInputDevice($id) -> Mock created")
                            }
                        } catch (e: Throwable) {
                            log("InputDevice mock failed for id=$id: ${e.message}")
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
    }
    
    /**
     * Erstellt ein Mock-InputDevice via Reflection.
     * Pixel 6 Geräte: Touchscreen (ID 1), GPIO-Keys (ID 2), Power Button (ID 3)
     */
    private fun createMockInputDevice(id: Int): android.view.InputDevice? {
        return try {
            // InputDevice hat keinen öffentlichen Konstruktor - nutze Reflection
            val clazz = android.view.InputDevice::class.java
            
            // Versuche den privaten Konstruktor
            val constructor = clazz.getDeclaredConstructor()
            constructor.isAccessible = true
            val device = constructor.newInstance()
            
            // Setze ID
            try {
                val idField = clazz.getDeclaredField("mId")
                idField.isAccessible = true
                idField.setInt(device, id)
            } catch (_: Throwable) {}
            
            // Setze Name basierend auf ID
            val name = when (id) {
                1 -> "sec_touchscreen"
                2 -> "gpio-keys"
                3 -> "Power Button"
                else -> "input$id"
            }
            try {
                val nameField = clazz.getDeclaredField("mName")
                nameField.isAccessible = true
                nameField.set(device, name)
            } catch (_: Throwable) {}
            
            // Setze Sources
            val sources = when (id) {
                1 -> 4098  // SOURCE_TOUCHSCREEN
                2 -> 257   // SOURCE_KEYBOARD
                3 -> 257   // SOURCE_KEYBOARD
                else -> 0
            }
            try {
                val sourcesField = clazz.getDeclaredField("mSources")
                sourcesField.isAccessible = true
                sourcesField.setInt(device, sources)
            } catch (_: Throwable) {}
            
            device
        } catch (e: Throwable) {
            log("createMockInputDevice failed: ${e.message}")
            null
        }
    }
    
    // =========================================================================
    // Helpers
    // =========================================================================
    
    private fun parseMacToBytes(mac: String): ByteArray? {
        return try {
            val parts = mac.split(":")
            if (parts.size != 6) null else ByteArray(6) { parts[it].toInt(16).toByte() }
        } catch (_: Exception) { null }
    }
    
    private fun hexToBytes(hex: String): ByteArray? {
        return try {
            val clean = hex.replace(Regex("[^0-9a-fA-F]"), "")
            if (clean.length < 2 || clean.length % 2 != 0) null
            else ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        } catch (_: Exception) { null }
    }
    
    private fun log(msg: String) {
        try { XposedBridge.log("[$TAG] $msg") } catch (_: Throwable) {}
    }
}
