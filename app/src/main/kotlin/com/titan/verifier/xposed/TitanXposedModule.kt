package com.titan.verifier.xposed

import android.content.ContentResolver
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.net.wifi.WifiInfo
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage

/**
 * Project Titan - LSPosed/Xposed Module (Phase 4.3)
 * 
 * Java Framework Hooks für vollständige Identitäts-Verschleierung:
 * - TelephonyManager: IMEI, IMSI, SIM Serial
 * - Settings.Secure: Android ID
 * - ContentResolver: GSF ID
 * - WifiInfo: MAC Address
 * 
 * Alle Werte werden aus der gemeinsamen Bridge-Datei gelesen,
 * um Konsistenz mit dem Zygisk-Modul zu gewährleisten.
 */
class TitanXposedModule : IXposedHookLoadPackage {

    companion object {
        private const val TAG = "TitanXposed"
        
        // Ziel-Packages (für selektives Hooking)
        private val TARGET_PACKAGES = setOf(
            "com.titan.verifier",
            "android",
            "com.android.phone",
            "com.google.android.gms",
            "com.google.android.gsf"
        )
        
        // GSF Content URI
        private const val GSF_CONTENT_URI = "content://com.google.android.gsf.gservices"
    }
    
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        // Nur für Ziel-Packages aktiv
        if (lpparam.packageName !in TARGET_PACKAGES) {
            return
        }
        
        log("Initializing for package: ${lpparam.packageName}")
        
        // Prüfe Bridge-Verfügbarkeit
        if (!TitanBridgeReader.isBridgeAvailable()) {
            log("WARNING: Bridge not available, hooks may not work correctly")
        }
        
        try {
            // === TelephonyManager Hooks ===
            hookTelephonyManager(lpparam)
            
            // === Settings.Secure Hook ===
            hookSettingsSecure(lpparam)
            
            // === ContentResolver Hook (GSF ID) ===
            hookContentResolver(lpparam)
            
            // === WifiInfo Hook ===
            hookWifiInfo(lpparam)
            
            log("All hooks installed for ${lpparam.packageName}")
            
        } catch (e: Throwable) {
            log("Error installing hooks: ${e.message}")
            XposedBridge.log(e)
        }
    }
    
    // =========================================================================
    // TelephonyManager Hooks
    // =========================================================================
    
    private fun hookTelephonyManager(lpparam: XC_LoadPackage.LoadPackageParam) {
        val tmClass = TelephonyManager::class.java
        
        // === getImei(int slotIndex) ===
        try {
            XposedHelpers.findAndHookMethod(
                tmClass,
                "getImei",
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val slotIndex = param.args[0] as Int
                        val spoofed = if (slotIndex == 0) {
                            TitanBridgeReader.getImei1()
                        } else {
                            TitanBridgeReader.getImei2()
                        }
                        
                        spoofed?.let {
                            param.result = it
                            log("Spoofed getImei($slotIndex) -> $it")
                        }
                    }
                }
            )
            log("Hooked TelephonyManager.getImei(int)")
        } catch (e: Throwable) {
            log("Failed to hook getImei(int): ${e.message}")
        }
        
        // === getImei() (no args) ===
        try {
            XposedHelpers.findAndHookMethod(
                tmClass,
                "getImei",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        TitanBridgeReader.getImei1()?.let {
                            param.result = it
                            log("Spoofed getImei() -> $it")
                        }
                    }
                }
            )
            log("Hooked TelephonyManager.getImei()")
        } catch (e: Throwable) {
            log("Failed to hook getImei(): ${e.message}")
        }
        
        // === getDeviceId(int slotIndex) ===
        try {
            XposedHelpers.findAndHookMethod(
                tmClass,
                "getDeviceId",
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val slotIndex = param.args[0] as Int
                        val spoofed = if (slotIndex == 0) {
                            TitanBridgeReader.getImei1()
                        } else {
                            TitanBridgeReader.getImei2()
                        }
                        
                        spoofed?.let {
                            param.result = it
                            log("Spoofed getDeviceId($slotIndex) -> $it")
                        }
                    }
                }
            )
            log("Hooked TelephonyManager.getDeviceId(int)")
        } catch (e: Throwable) {
            log("Failed to hook getDeviceId(int): ${e.message}")
        }
        
        // === getDeviceId() (no args) ===
        try {
            XposedHelpers.findAndHookMethod(
                tmClass,
                "getDeviceId",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        TitanBridgeReader.getImei1()?.let {
                            param.result = it
                            log("Spoofed getDeviceId() -> $it")
                        }
                    }
                }
            )
            log("Hooked TelephonyManager.getDeviceId()")
        } catch (e: Throwable) {
            log("Failed to hook getDeviceId(): ${e.message}")
        }
        
        // === getSubscriberId() - IMSI ===
        try {
            XposedHelpers.findAndHookMethod(
                tmClass,
                "getSubscriberId",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        TitanBridgeReader.getImsi()?.let {
                            param.result = it
                            log("Spoofed getSubscriberId() -> $it")
                        }
                    }
                }
            )
            log("Hooked TelephonyManager.getSubscriberId()")
        } catch (e: Throwable) {
            log("Failed to hook getSubscriberId(): ${e.message}")
        }
        
        // === getSubscriberId(int subId) ===
        try {
            XposedHelpers.findAndHookMethod(
                tmClass,
                "getSubscriberId",
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        TitanBridgeReader.getImsi()?.let {
                            param.result = it
                            log("Spoofed getSubscriberId(int) -> $it")
                        }
                    }
                }
            )
            log("Hooked TelephonyManager.getSubscriberId(int)")
        } catch (e: Throwable) {
            log("Failed to hook getSubscriberId(int): ${e.message}")
        }
        
        // === getSimSerialNumber() - ICCID ===
        try {
            XposedHelpers.findAndHookMethod(
                tmClass,
                "getSimSerialNumber",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        TitanBridgeReader.getSimSerial()?.let {
                            param.result = it
                            log("Spoofed getSimSerialNumber() -> $it")
                        }
                    }
                }
            )
            log("Hooked TelephonyManager.getSimSerialNumber()")
        } catch (e: Throwable) {
            log("Failed to hook getSimSerialNumber(): ${e.message}")
        }
        
        // === getSimSerialNumber(int subId) ===
        try {
            XposedHelpers.findAndHookMethod(
                tmClass,
                "getSimSerialNumber",
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        TitanBridgeReader.getSimSerial()?.let {
                            param.result = it
                            log("Spoofed getSimSerialNumber(int) -> $it")
                        }
                    }
                }
            )
            log("Hooked TelephonyManager.getSimSerialNumber(int)")
        } catch (e: Throwable) {
            log("Failed to hook getSimSerialNumber(int): ${e.message}")
        }
    }
    
    // =========================================================================
    // Settings.Secure Hook (Android ID)
    // =========================================================================
    
    private fun hookSettingsSecure(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                Settings.Secure::class.java,
                "getString",
                ContentResolver::class.java,
                String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val name = param.args[1] as? String ?: return
                        
                        if (name == Settings.Secure.ANDROID_ID) {
                            TitanBridgeReader.getAndroidId()?.let {
                                param.result = it
                                log("Spoofed Settings.Secure.ANDROID_ID -> $it")
                            }
                        }
                    }
                }
            )
            log("Hooked Settings.Secure.getString()")
        } catch (e: Throwable) {
            log("Failed to hook Settings.Secure.getString(): ${e.message}")
        }
        
        // Auch getStringForUser hooken (interner API Call)
        try {
            XposedHelpers.findAndHookMethod(
                Settings.Secure::class.java,
                "getStringForUser",
                ContentResolver::class.java,
                String::class.java,
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val name = param.args[1] as? String ?: return
                        
                        if (name == Settings.Secure.ANDROID_ID) {
                            TitanBridgeReader.getAndroidId()?.let {
                                param.result = it
                                log("Spoofed Settings.Secure.getStringForUser(ANDROID_ID) -> $it")
                            }
                        }
                    }
                }
            )
            log("Hooked Settings.Secure.getStringForUser()")
        } catch (e: Throwable) {
            // Diese Methode existiert möglicherweise nicht auf allen Android-Versionen
        }
    }
    
    // =========================================================================
    // ContentResolver Hook (GSF ID)
    // =========================================================================
    
    private fun hookContentResolver(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
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
                        val uri = param.args[0] as? Uri ?: return
                        
                        // GSF GServices Query abfangen
                        if (uri.toString().startsWith(GSF_CONTENT_URI)) {
                            val selectionArgs = param.args[3] as? Array<*>
                            
                            // Prüfe ob android_id abgefragt wird
                            if (selectionArgs?.any { it == "android_id" } == true) {
                                val spoofedGsf = TitanBridgeReader.getGsfId()
                                if (spoofedGsf != null) {
                                    // Original-Cursor durch gespooften ersetzen
                                    val cursor = param.result as? Cursor
                                    if (cursor != null && cursor.moveToFirst()) {
                                        // MatrixCursor mit gespooftem Wert erstellen
                                        val columns = Array(cursor.columnCount) { cursor.getColumnName(it) }
                                        val matrixCursor = MatrixCursor(columns)
                                        matrixCursor.addRow(arrayOf("android_id", spoofedGsf))
                                        param.result = matrixCursor
                                        log("Spoofed GSF ID via ContentResolver -> $spoofedGsf")
                                    }
                                }
                            }
                        }
                    }
                }
            )
            log("Hooked ContentResolver.query()")
        } catch (e: Throwable) {
            log("Failed to hook ContentResolver.query(): ${e.message}")
        }
    }
    
    // =========================================================================
    // WifiInfo Hook (MAC Address)
    // =========================================================================
    
    private fun hookWifiInfo(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                WifiInfo::class.java,
                "getMacAddress",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        TitanBridgeReader.getWifiMac()?.let {
                            param.result = it
                            log("Spoofed WifiInfo.getMacAddress() -> $it")
                        }
                    }
                }
            )
            log("Hooked WifiInfo.getMacAddress()")
        } catch (e: Throwable) {
            log("Failed to hook WifiInfo.getMacAddress(): ${e.message}")
        }
        
        // getBSSID könnte auch relevant sein
        try {
            XposedHelpers.findAndHookMethod(
                WifiInfo::class.java,
                "getBSSID",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        // Optional: BSSID kann auch gespooft werden
                        // Für jetzt lassen wir es original
                    }
                }
            )
        } catch (e: Throwable) {
            // Ignorieren
        }
    }
    
    // =========================================================================
    // Logging
    // =========================================================================
    
    private fun log(msg: String) {
        XposedBridge.log("[$TAG] $msg")
    }
}
