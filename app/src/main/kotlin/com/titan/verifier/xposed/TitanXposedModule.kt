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
import java.net.NetworkInterface
import java.util.UUID

/**
 * Project Titan - LSPosed/Xposed Module (Phase 4.8 - Surgical Safe Edition)
 * 
 * FAIL-SAFE Hooks: Wenn Bridge nicht lesbar, Original-Wert zurückgeben.
 * Keine Crashes, keine Bootloops.
 * 
 * Surgical Fixes für:
 * - GSF ID (GServices + ContentResolver)
 * - WiFi MAC (WifiInfo + NetworkInterface)
 * - Widevine ID (MediaDrm)
 */
class TitanXposedModule : IXposedHookLoadPackage {

    companion object {
        private const val TAG = "TITAN-SAFE-HOOK"
        
        private val TARGET_PACKAGES = setOf(
            "com.titan.verifier",
            "android",
            "com.android.phone",
            "com.google.android.gms",
            "com.google.android.gsf"
        )
        
        private const val GSF_CONTENT_URI = "content://com.google.android.gsf.gservices"
    }
    
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName !in TARGET_PACKAGES) return
        
        log("Initializing SAFE hooks for: ${lpparam.packageName}")
        
        // Fail-Safe: Prüfe Bridge zuerst
        val bridgeAvailable = try {
            TitanBridgeReader.isBridgeAvailable()
        } catch (e: Throwable) {
            log("Bridge check failed: ${e.message}")
            false
        }
        
        if (!bridgeAvailable) {
            log("WARNING: Bridge not available - hooks will pass-through to original")
        }
        
        // === Surgical Hook Installation ===
        safeHook("TelephonyManager") { hookTelephonyManager(lpparam) }
        safeHook("Settings.Secure") { hookSettingsSecure(lpparam) }
        safeHook("SystemProperties") { hookSystemProperties(lpparam) }
        safeHook("ContentResolver-GSF") { hookContentResolverGsf(lpparam) }
        safeHook("GServices") { hookGServices(lpparam) }
        safeHook("WifiInfo") { hookWifiInfo(lpparam) }
        safeHook("NetworkInterface") { hookNetworkInterface(lpparam) }
        safeHook("MediaDrm-Widevine") { hookMediaDrmWidevine(lpparam) }
        safeHook("InputManager") { hookInputManager(lpparam) }
        
        log("All SAFE hooks installed for ${lpparam.packageName}")
    }
    
    /**
     * Wrapper für sichere Hook-Installation mit Logging.
     */
    private inline fun safeHook(name: String, block: () -> Unit) {
        try {
            block()
            log("Applied: $name")
        } catch (e: Throwable) {
            log("Failed: $name - ${e.message}")
        }
    }
    
    /**
     * Fail-Safe Getter: Gibt null zurück wenn Bridge nicht lesbar.
     */
    private fun safeGetBridgeValue(getter: () -> String?): String? {
        return try {
            getter()
        } catch (e: Throwable) {
            log("Bridge read error: ${e.message}")
            null
        }
    }
    
    // =========================================================================
    // TelephonyManager Hooks (IMEI, IMSI, SIM, Operator)
    // =========================================================================
    
    private fun hookTelephonyManager(lpparam: XC_LoadPackage.LoadPackageParam) {
        val tmClass = TelephonyManager::class.java
        
        // getImei(int)
        tryHook(tmClass, "getImei", Int::class.javaPrimitiveType) { param ->
            val slot = param.args[0] as Int
            val value = safeGetBridgeValue { 
                if (slot == 0) TitanBridgeReader.getImei1() else TitanBridgeReader.getImei2()
            }
            if (value != null) {
                param.result = value
                log("Spoofed getImei($slot) -> $value")
            }
        }
        
        // getImei()
        tryHook(tmClass, "getImei") { param ->
            safeGetBridgeValue { TitanBridgeReader.getImei1() }?.let {
                param.result = it
                log("Spoofed getImei() -> $it")
            }
        }
        
        // getDeviceId variants
        tryHook(tmClass, "getDeviceId", Int::class.javaPrimitiveType) { param ->
            val slot = param.args[0] as Int
            safeGetBridgeValue { 
                if (slot == 0) TitanBridgeReader.getImei1() else TitanBridgeReader.getImei2()
            }?.let {
                param.result = it
                log("Spoofed getDeviceId($slot) -> $it")
            }
        }
        
        tryHook(tmClass, "getDeviceId") { param ->
            safeGetBridgeValue { TitanBridgeReader.getImei1() }?.let {
                param.result = it
                log("Spoofed getDeviceId() -> $it")
            }
        }
        
        // getSubscriberId (IMSI)
        tryHook(tmClass, "getSubscriberId") { param ->
            safeGetBridgeValue { TitanBridgeReader.getImsi() }?.let {
                param.result = it
                log("Spoofed getSubscriberId() -> $it")
            }
        }
        
        tryHook(tmClass, "getSubscriberId", Int::class.javaPrimitiveType) { param ->
            safeGetBridgeValue { TitanBridgeReader.getImsi() }?.let {
                param.result = it
                log("Spoofed getSubscriberId(int) -> $it")
            }
        }
        
        // getSimSerialNumber (ICCID)
        tryHook(tmClass, "getSimSerialNumber") { param ->
            safeGetBridgeValue { TitanBridgeReader.getSimSerial() }?.let {
                param.result = it
                log("Spoofed getSimSerialNumber() -> $it")
            }
        }
        
        tryHook(tmClass, "getSimSerialNumber", Int::class.javaPrimitiveType) { param ->
            safeGetBridgeValue { TitanBridgeReader.getSimSerial() }?.let {
                param.result = it
                log("Spoofed getSimSerialNumber(int) -> $it")
            }
        }
        
        // getNetworkOperatorName
        tryHook(tmClass, "getNetworkOperatorName") { param ->
            safeGetBridgeValue { TitanBridgeReader.getOperatorName() }?.let {
                param.result = it
                log("Spoofed getNetworkOperatorName() -> $it")
            }
        }
        
        // getSimOperatorName
        tryHook(tmClass, "getSimOperatorName") { param ->
            safeGetBridgeValue { TitanBridgeReader.getOperatorName() }?.let {
                param.result = it
                log("Spoofed getSimOperatorName() -> $it")
            }
        }
    }
    
    // =========================================================================
    // Settings.Secure (Android ID)
    // =========================================================================
    
    private fun hookSettingsSecure(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedHelpers.findAndHookMethod(
            Settings.Secure::class.java,
            "getString",
            ContentResolver::class.java,
            String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        val name = param.args[1] as? String ?: return
                        
                        if (name == Settings.Secure.ANDROID_ID) {
                            safeGetBridgeValue { TitanBridgeReader.getAndroidId() }?.let {
                                param.result = it
                                log("Spoofed ANDROID_ID -> $it")
                            }
                        }
                    } catch (e: Throwable) {
                        log("Settings.Secure hook error: ${e.message}")
                        // Fail-safe: Let original method run
                    }
                }
            }
        )
    }
    
    // =========================================================================
    // SystemProperties (GSF ID + Serial backup)
    // =========================================================================
    
    private fun hookSystemProperties(lpparam: XC_LoadPackage.LoadPackageParam) {
        val spClass = XposedHelpers.findClass("android.os.SystemProperties", lpparam.classLoader)
        
        XposedHelpers.findAndHookMethod(spClass, "get", String::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                try {
                    val key = param.args[0] as? String ?: return
                    handlePropertyGet(key, param)
                } catch (e: Throwable) {
                    // Fail-safe: Original continues
                }
            }
        })
        
        XposedHelpers.findAndHookMethod(spClass, "get", String::class.java, String::class.java, object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                try {
                    val key = param.args[0] as? String ?: return
                    handlePropertyGet(key, param)
                } catch (e: Throwable) {
                    // Fail-safe
                }
            }
        })
    }
    
    private fun handlePropertyGet(key: String, param: XC_MethodHook.MethodHookParam) {
        val keyLower = key.lowercase()
        
        // GSF ID
        if (keyLower.contains("gsf") || key == "ro.com.google.gservices.gsf.id") {
            safeGetBridgeValue { TitanBridgeReader.getGsfId() }?.let {
                param.result = it
                log("Spoofed SystemProperties($key) -> $it")
            }
            return
        }
        
        // Serial backup
        if (key == "ro.serialno" || key == "ro.boot.serialno") {
            safeGetBridgeValue { TitanBridgeReader.getSerial() }?.let {
                param.result = it
                log("Spoofed SystemProperties($key) -> $it")
            }
        }
    }
    
    // =========================================================================
    // SURGICAL GSF Hook: ContentResolver.query
    // =========================================================================
    
    private fun hookContentResolverGsf(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedHelpers.findAndHookMethod(
            ContentResolver::class.java,
            "query",
            Uri::class.java,
            Array<String>::class.java,
            String::class.java,
            Array<String>::class.java,
            String::class.java,
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    try {
                        val uri = param.args[0] as? Uri ?: return
                        if (!uri.toString().startsWith(GSF_CONTENT_URI)) return
                        
                        val gsfId = safeGetBridgeValue { TitanBridgeReader.getGsfId() } ?: return
                        val cursor = param.result as? Cursor ?: return
                        
                        // Sicher: Nur wenn Cursor gültig ist
                        if (cursor.isClosed) return
                        
                        // Erstelle Matrix-Cursor mit gespoofter GSF ID
                        val matrixCursor = MatrixCursor(arrayOf("name", "value"))
                        matrixCursor.addRow(arrayOf("android_id", gsfId))
                        
                        param.result = matrixCursor
                        log("Spoofed GSF via ContentResolver -> $gsfId")
                        
                    } catch (e: Throwable) {
                        log("GSF ContentResolver hook error: ${e.message}")
                        // Fail-safe: Original result stays
                    }
                }
            }
        )
    }
    
    // =========================================================================
    // SURGICAL GSF Hook: Gservices.getString direkt
    // =========================================================================
    
    private fun hookGServices(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            val gservicesClass = XposedHelpers.findClass(
                "com.google.android.gsf.Gservices",
                lpparam.classLoader
            )
            
            // getString(ContentResolver, String)
            XposedHelpers.findAndHookMethod(
                gservicesClass,
                "getString",
                ContentResolver::class.java,
                String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            val key = param.args[1] as? String ?: return
                            if (key == "android_id" || key.lowercase().contains("gsf")) {
                                safeGetBridgeValue { TitanBridgeReader.getGsfId() }?.let {
                                    param.result = it
                                    log("Spoofed Gservices.getString($key) -> $it")
                                }
                            }
                        } catch (e: Throwable) {
                            // Fail-safe
                        }
                    }
                }
            )
            
            // getLong mit GSF ID
            XposedHelpers.findAndHookMethod(
                gservicesClass,
                "getLong",
                ContentResolver::class.java,
                String::class.java,
                Long::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            val key = param.args[1] as? String ?: return
                            if (key == "android_id" || key.lowercase().contains("gsf")) {
                                safeGetBridgeValue { TitanBridgeReader.getGsfId() }?.let { gsfStr ->
                                    val gsfLong = gsfStr.toLongOrNull()
                                    if (gsfLong != null) {
                                        param.result = gsfLong
                                        log("Spoofed Gservices.getLong($key) -> $gsfLong")
                                    }
                                }
                            }
                        } catch (e: Throwable) {
                            // Fail-safe
                        }
                    }
                }
            )
            
            log("Hooked Gservices class directly")
        } catch (e: Throwable) {
            // Gservices class might not exist in all contexts
            log("Gservices class not found (expected in non-GMS context)")
        }
    }
    
    // =========================================================================
    // SURGICAL MAC Hook: WifiInfo
    // =========================================================================
    
    private fun hookWifiInfo(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedHelpers.findAndHookMethod(
            WifiInfo::class.java,
            "getMacAddress",
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        safeGetBridgeValue { TitanBridgeReader.getWifiMac() }?.let {
                            param.result = it
                            log("Spoofed WifiInfo.getMacAddress() -> $it")
                        }
                    } catch (e: Throwable) {
                        // Fail-safe
                    }
                }
            }
        )
    }
    
    // =========================================================================
    // SURGICAL MAC Hook: NetworkInterface.getHardwareAddress()
    // =========================================================================
    
    private fun hookNetworkInterface(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedHelpers.findAndHookMethod(
            NetworkInterface::class.java,
            "getHardwareAddress",
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        val ni = param.thisObject as? NetworkInterface ?: return
                        val name = ni.name ?: return
                        
                        // Nur wlan0 und eth0 spoofen
                        if (name != "wlan0" && name != "eth0") return
                        
                        val macStr = safeGetBridgeValue { TitanBridgeReader.getWifiMac() } ?: return
                        val macBytes = parseMacToBytes(macStr)
                        
                        if (macBytes != null) {
                            param.result = macBytes
                            log("Spoofed NetworkInterface($name).getHardwareAddress() -> $macStr")
                        }
                    } catch (e: Throwable) {
                        log("NetworkInterface hook error: ${e.message}")
                        // Fail-safe: Original continues
                    }
                }
            }
        )
    }
    
    /**
     * Parst MAC-String zu Byte-Array (null-safe).
     */
    private fun parseMacToBytes(mac: String?): ByteArray? {
        if (mac.isNullOrEmpty()) return null
        
        return try {
            val parts = mac.split(":")
            if (parts.size != 6) return null
            
            ByteArray(6) { i ->
                parts[i].toInt(16).toByte()
            }
        } catch (e: Exception) {
            null
        }
    }
    
    // =========================================================================
    // SURGICAL Widevine Hook: MediaDrm.getPropertyByteArray
    // =========================================================================
    
    private fun hookMediaDrmWidevine(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedHelpers.findAndHookMethod(
            MediaDrm::class.java,
            "getPropertyByteArray",
            String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        val property = param.args[0] as? String ?: return
                        
                        // deviceUniqueId ist die Widevine Device ID
                        if (property == MediaDrm.PROPERTY_DEVICE_UNIQUE_ID || 
                            property == "deviceUniqueId" ||
                            property.lowercase().contains("deviceuniqueid")) {
                            
                            val widevineHex = safeGetBridgeValue { TitanBridgeReader.getWidevineId() }
                            if (!widevineHex.isNullOrEmpty()) {
                                val bytes = hexToBytes(widevineHex)
                                if (bytes != null && bytes.isNotEmpty()) {
                                    param.result = bytes
                                    log("Spoofed MediaDrm.deviceUniqueId -> ${bytes.size} bytes")
                                }
                            }
                        }
                    } catch (e: Throwable) {
                        log("MediaDrm hook error: ${e.message}")
                        // Fail-safe: Original continues
                    }
                }
            }
        )
        
        // Auch getPropertyString hooken
        XposedHelpers.findAndHookMethod(
            MediaDrm::class.java,
            "getPropertyString",
            String::class.java,
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        val property = param.args[0] as? String ?: return
                        
                        if (property.lowercase().contains("deviceid") ||
                            property.lowercase().contains("unique")) {
                            safeGetBridgeValue { TitanBridgeReader.getWidevineId() }?.let {
                                param.result = it
                                log("Spoofed MediaDrm.getPropertyString($property) -> $it")
                            }
                        }
                    } catch (e: Throwable) {
                        // Fail-safe
                    }
                }
            }
        )
    }
    
    /**
     * Konvertiert Hex-String zu Byte-Array (null-safe).
     */
    private fun hexToBytes(hex: String?): ByteArray? {
        if (hex.isNullOrEmpty()) return null
        
        return try {
            val clean = hex.replace(Regex("[^0-9a-fA-F]"), "")
            if (clean.length < 2 || clean.length % 2 != 0) return null
            
            ByteArray(clean.length / 2) { i ->
                clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        } catch (e: Exception) {
            null
        }
    }
    
    // =========================================================================
    // InputManager Hook (Device IDs - Anonymität)
    // =========================================================================
    
    private fun hookInputManager(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedHelpers.findAndHookMethod(
            InputManager::class.java,
            "getInputDeviceIds",
            object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        param.result = IntArray(0)
                        log("Spoofed InputManager.getInputDeviceIds() -> empty")
                    } catch (e: Throwable) {
                        // Fail-safe
                    }
                }
            }
        )
    }
    
    // =========================================================================
    // Helper: Vararg Hook Wrapper
    // =========================================================================
    
    private fun tryHook(clazz: Class<*>, methodName: String, vararg paramTypes: Any?, callback: (XC_MethodHook.MethodHookParam) -> Unit) {
        try {
            val args = mutableListOf<Any?>()
            args.addAll(paramTypes)
            args.add(object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        callback(param)
                    } catch (e: Throwable) {
                        log("Hook callback error: ${e.message}")
                    }
                }
            })
            
            if (paramTypes.isEmpty()) {
                XposedHelpers.findAndHookMethod(clazz, methodName, args.last())
            } else {
                XposedHelpers.findAndHookMethod(clazz, methodName, *args.toTypedArray())
            }
        } catch (e: Throwable) {
            // Method might not exist
        }
    }
    
    // =========================================================================
    // Logging
    // =========================================================================
    
    private fun log(msg: String) {
        try {
            XposedBridge.log("[$TAG] $msg")
        } catch (_: Throwable) {}
    }
}
