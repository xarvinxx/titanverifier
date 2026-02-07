package com.titan.verifier.xposed

import android.content.ContentResolver
import android.database.Cursor
import android.database.MatrixCursor
import android.hardware.input.InputManager
import android.media.MediaDrm
import android.net.Uri
import android.net.wifi.WifiInfo
import android.os.BatteryManager
import android.provider.Settings
import android.telephony.TelephonyManager
import android.util.DisplayMetrics
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
 * Project Titan - LSPosed Module (Phase 10.0 - Full Spectrum Stealth)
 * 
 * EXTENDED SCOPE: Verifier, TikTok, GMS, Play Store
 * FULL COVERAGE: Build Props, Display, Sensors, Battery, GSF, Widevine, MAC, All IDs
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
            "android",                       // System Framework
            "com.androidfung.drminfo",      // DRM Info App
            "tw.reh.deviceid"               // Device ID App
        )
        
        private const val GSF_CONTENT_URI = "content://com.google.android.gsf.gservices"
        
        // MAC-Pfade die wir abfangen
        private val MAC_PATHS = setOf(
            "/sys/class/net/wlan0/address",
            "/sys/class/net/eth0/address",
            "/proc/net/arp"
        )
        
        // =====================================================================
        // Pixel 6 Build Properties (Hardcoded – MÜSSEN konsistent sein!)
        // =====================================================================
        private val PIXEL6_BUILD_FIELDS = mapOf(
            "MANUFACTURER"  to "Google",
            "MODEL"         to "Pixel 6",
            "BRAND"         to "google",
            "PRODUCT"       to "oriole",
            "DEVICE"        to "oriole",
            "BOARD"         to "oriole",
            "HARDWARE"      to "oriole",
            "DISPLAY"       to "AP1A.240505.004",
            "ID"            to "AP1A.240505.004",
            "FINGERPRINT"   to "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys",
            "TYPE"          to "user",
            "TAGS"          to "release-keys",
            "HOST"          to "abfarm-release-rbe-64-00044",
            "USER"          to "android-build"
        )
        
        private val PIXEL6_VERSION_FIELDS = mapOf(
            "SDK_INT"           to 34,
            "RELEASE"           to "14",
            "SECURITY_PATCH"    to "2024-05-05",
            "INCREMENTAL"       to "11583682",
            "CODENAME"          to "REL",
            "BASE_OS"           to "",
            "PREVIEW_SDK_INT"   to 0
        )
        
        // Pixel 6 SystemProperties Map (für handlePropertyGet)
        private val PIXEL6_PROP_MAP = mapOf(
            "ro.product.manufacturer"          to "Google",
            "ro.product.model"                 to "Pixel 6",
            "ro.product.brand"                 to "google",
            "ro.product.name"                  to "oriole",
            "ro.product.device"                to "oriole",
            "ro.product.board"                 to "oriole",
            "ro.hardware"                      to "oriole",
            "ro.hardware.chipname"             to "gs101",
            "ro.build.display.id"              to "AP1A.240505.004",
            "ro.build.description"             to "oriole-user 14 AP1A.240505.004 11583682 release-keys",
            "ro.build.fingerprint"             to "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys",
            "ro.build.product"                 to "oriole",
            "ro.build.type"                    to "user",
            "ro.build.tags"                    to "release-keys",
            "ro.build.id"                      to "AP1A.240505.004",
            "ro.build.version.sdk"             to "34",
            "ro.build.version.release"         to "14",
            "ro.build.version.security_patch"  to "2024-05-05",
            "ro.build.version.incremental"     to "11583682",
            "ro.build.version.codename"        to "REL",
            "ro.soc.manufacturer"              to "Google",
            "ro.soc.model"                     to "Tensor",
            "ro.product.first_api_level"       to "31",
            "ro.product.system.brand"          to "google",
            "ro.product.system.model"          to "Pixel 6",
            "ro.product.system.manufacturer"   to "Google",
            "ro.product.system.device"         to "oriole",
            "ro.product.vendor.brand"          to "google",
            "ro.product.vendor.model"          to "Pixel 6",
            "ro.product.vendor.manufacturer"   to "Google",
            "ro.product.vendor.device"         to "oriole",
            "ro.bootimage.build.fingerprint"   to "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys",
            "ro.vendor.build.fingerprint"      to "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys",
            "ro.odm.build.fingerprint"         to "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys",
            "ro.system.build.fingerprint"      to "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys"
        )
        
        // Pixel 6 Display-Spezifikationen
        private const val PIXEL6_WIDTH = 1080
        private const val PIXEL6_HEIGHT = 2400
        private const val PIXEL6_DENSITY_DPI = 411
        private const val PIXEL6_DENSITY = 2.5625f    // 411 / 160
        private const val PIXEL6_SCALED_DENSITY = 2.5625f
        private const val PIXEL6_XDPI = 411.0f
        private const val PIXEL6_YDPI = 411.0f
        
        // Pixel 6 Sensor-Liste (echte Hardware-Sensoren)
        private val PIXEL6_SENSOR_NAMES = setOf(
            "BMI260 Accelerometer", "BMI260 Gyroscope",         // Bosch
            "LSM6DSR Accelerometer", "LSM6DSR Gyroscope",       // STMicro
            "AK09918 Magnetometer",                              // AKM
            "BMP390 Pressure",                                   // Bosch
            "TMD3719 Proximity", "TMD3719 Light",                // AMS
            "Gravity", "Linear Acceleration", "Rotation Vector",
            "Game Rotation Vector", "Geomagnetic Rotation Vector",
            "Significant Motion", "Step Detector", "Step Counter",
            "Tilt Detector", "Pick Up Gesture", "Stationary Detect"
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
        private var cachedPhoneNumber: String? = null
        private var cachedSimOperator: String? = null
        private var cachedSimOperatorName: String? = null
        private var cachedVoicemailNumber: String? = null
    }
    
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName !in TARGET_PACKAGES) return
        
        log("Phase 10.0 Full Spectrum Stealth for: ${lpparam.packageName}")
        
        // ===== Build & Hardware Identity =====
        safeHook("Build-Fields") { hookBuildFields(lpparam) }
        safeHook("SystemProperties") { hookSystemProperties(lpparam) }
        
        // ===== Core Identity Hooks =====
        safeHook("TelephonyManager") { hookTelephonyManager() }
        safeHook("TelephonyExtra") { hookTelephonyExtra() }
        safeHook("Settings.Secure") { hookSettingsSecure() }
        
        // ===== GSF Total Coverage =====
        safeHook("GSF-ContentResolver") { hookGsfContentResolver() }
        safeHook("GSF-ContentProviderClient") { hookGsfContentProviderClient(lpparam) }
        safeHook("Gservices-Direct") { hookGservicesDirect(lpparam) }
        
        // ===== MAC Total Coverage =====
        safeHook("WifiInfo") { hookWifiInfo() }
        safeHook("NetworkInterface") { hookNetworkInterface() }
        safeHook("FileInputStream-MAC") { hookFileInputStreamMac() }
        safeHook("File.readText-MAC") { hookFileReadTextMac(lpparam) }
        
        // ===== DRM =====
        safeHook("MediaDrm-Widevine") { hookMediaDrm() }
        
        // ===== Hardware Stealth =====
        safeHook("InputManager") { hookInputManager() }
        safeHook("DisplayMetrics") { hookDisplayMetrics() }
        safeHook("SensorManager") { hookSensorManager(lpparam) }
        safeHook("BatteryManager") { hookBatteryManager() }
        safeHook("SensorJitter") { hookSensorJitter(lpparam) }
        safeHook("AdvertisingId") { hookAdvertisingId(lpparam) }
        
        log("Full Spectrum hooks complete for ${lpparam.packageName}")
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
            cachedPhoneNumber = TitanBridgeReader.getPhoneNumber()
            cachedSimOperator = TitanBridgeReader.getSimOperator()
            cachedSimOperatorName = TitanBridgeReader.getSimOperatorName()
            cachedVoicemailNumber = TitanBridgeReader.getVoicemailNumber()
            bridgeLoaded = true
            log("Bridge loaded: GSF=$cachedGsfId, MAC=$cachedMac, WV=$cachedWidevine, Phone=$cachedPhoneNumber")
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
        
        // Bridge-basierte Identity Properties
        when {
            key.contains("gsf", ignoreCase = true) || key == "ro.com.google.gservices.gsf.id" -> {
                cachedGsfId?.let { param.result = it; log("Spoofed SystemProperties($key) -> $it") }
                return
            }
            key == "ro.serialno" || key == "ro.boot.serialno" -> {
                cachedSerial?.let { param.result = it }
                return
            }
        }
        
        // Hardcoded Pixel 6 Build Properties
        PIXEL6_PROP_MAP[key]?.let { value ->
            param.result = value
            return
        }
    }
    
    // =========================================================================
    // GSF Total Coverage - ContentResolver.query
    // =========================================================================
    
    private fun hookGsfContentResolver() {
        // Variante 1: 5-arg query (ältere API)
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
                            val cursor = MatrixCursor(arrayOf("name", "value"))
                            cursor.addRow(arrayOf("android_id", gsfId))
                            cursor.addRow(arrayOf("gsf_id", gsfId))
                            cursor.addRow(arrayOf("device_id", gsfId))
                            param.result = cursor
                            log("GSF query(5-arg) -> $gsfId")
                        }
                    }
                }
            }
        )
        
        // Variante 2: Bundle-basierte query (Android 11+ / API 30+)
        try {
            XposedHelpers.findAndHookMethod(
                ContentResolver::class.java, "query",
                Uri::class.java, Array<String>::class.java, android.os.Bundle::class.java,
                android.os.CancellationSignal::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val uri = param.args[0] as? Uri ?: return
                        val uriStr = uri.toString()
                        
                        if (uriStr.contains("gsf") || uriStr.contains("gservices")) {
                            ensureBridgeLoaded()
                            cachedGsfId?.let { gsfId ->
                                val cursor = MatrixCursor(arrayOf("name", "value"))
                                cursor.addRow(arrayOf("android_id", gsfId))
                                cursor.addRow(arrayOf("gsf_id", gsfId))
                                cursor.addRow(arrayOf("device_id", gsfId))
                                param.result = cursor
                                log("GSF query(Bundle) -> $gsfId")
                            }
                        }
                    }
                }
            )
            log("GSF Bundle-query hook OK")
        } catch (_: Throwable) {}
        
        // Variante 3: 6-arg query mit CancellationSignal (API 16+)
        try {
            XposedHelpers.findAndHookMethod(
                ContentResolver::class.java, "query",
                Uri::class.java, Array<String>::class.java, String::class.java,
                Array<String>::class.java, String::class.java,
                android.os.CancellationSignal::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val uri = param.args[0] as? Uri ?: return
                        val uriStr = uri.toString()
                        
                        if (uriStr.contains("gsf") || uriStr.contains("gservices")) {
                            ensureBridgeLoaded()
                            cachedGsfId?.let { gsfId ->
                                val cursor = MatrixCursor(arrayOf("name", "value"))
                                cursor.addRow(arrayOf("android_id", gsfId))
                                cursor.addRow(arrayOf("gsf_id", gsfId))
                                cursor.addRow(arrayOf("device_id", gsfId))
                                param.result = cursor
                                log("GSF query(6-arg+signal) -> $gsfId")
                            }
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
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
    // Build Fields (android.os.Build + Build.VERSION) – Phase 10.0
    // =========================================================================
    
    private fun hookBuildFields(lpparam: XC_LoadPackage.LoadPackageParam) {
        // android.os.Build Felder überschreiben (static final via Reflection)
        val buildClass = XposedHelpers.findClass("android.os.Build", lpparam.classLoader)
        
        PIXEL6_BUILD_FIELDS.forEach { (fieldName, value) ->
            try {
                val field = buildClass.getDeclaredField(fieldName)
                field.isAccessible = true
                
                // Remove final modifier
                val modifiersField = try {
                    java.lang.reflect.Field::class.java.getDeclaredField("modifiers")
                } catch (_: Throwable) {
                    // Android 12+ nutzt "accessFlags"
                    java.lang.reflect.Field::class.java.getDeclaredField("accessFlags")
                }
                modifiersField.isAccessible = true
                modifiersField.setInt(field, field.modifiers and java.lang.reflect.Modifier.FINAL.inv())
                
                field.set(null, value)
                log("Build.$fieldName = $value")
            } catch (e: Throwable) {
                // Fallback: XposedHelpers für hartnäckige Felder
                try {
                    XposedHelpers.setStaticObjectField(buildClass, fieldName, value)
                } catch (_: Throwable) {}
            }
        }
        
        // android.os.Build.VERSION Felder
        val versionClass = XposedHelpers.findClass("android.os.Build\$VERSION", lpparam.classLoader)
        PIXEL6_VERSION_FIELDS.forEach { (fieldName, value) ->
            try {
                XposedHelpers.setStaticObjectField(versionClass, fieldName, value)
                log("Build.VERSION.$fieldName = $value")
            } catch (_: Throwable) {}
        }
        
        log("Build fields overridden (${PIXEL6_BUILD_FIELDS.size} + ${PIXEL6_VERSION_FIELDS.size} fields)")
        
        // Hook Build.getSerial() - gibt Bridge-Serial zurück
        try {
            XposedHelpers.findAndHookMethod(
                buildClass, "getSerial",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        ensureBridgeLoaded()
                        cachedSerial?.let { 
                            param.result = it
                            log("Build.getSerial() -> $it")
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
        
        // Hook Build.SERIAL Feld direkt
        try {
            ensureBridgeLoaded()
            cachedSerial?.let { serial ->
                XposedHelpers.setStaticObjectField(buildClass, "SERIAL", serial)
                log("Build.SERIAL = $serial")
            }
        } catch (_: Throwable) {}
    }
    
    // =========================================================================
    // Telephony Extra – Phase 10.0
    // =========================================================================
    
    private fun hookTelephonyExtra() {
        val tm = TelephonyManager::class.java
        
        // getLine1Number (Telefonnummer)
        try {
            XposedHelpers.findAndHookMethod(tm, "getLine1Number", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    val number = cachedPhoneNumber ?: "+12025551234"
                    param.result = number
                    log("TelephonyManager.getLine1Number -> $number")
                }
            })
        } catch (_: Throwable) {}
        
        // getVoiceMailNumber
        try {
            XposedHelpers.findAndHookMethod(tm, "getVoiceMailNumber", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    val vm = cachedVoicemailNumber ?: "+18056377243"
                    param.result = vm
                }
            })
        } catch (_: Throwable) {}
        
        // getSimOperator (MCC+MNC, z.B. "310260" = T-Mobile US)
        try {
            XposedHelpers.findAndHookMethod(tm, "getSimOperator", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    param.result = cachedSimOperator ?: "310260"
                }
            })
        } catch (_: Throwable) {}
        
        // getSimOperatorName
        try {
            XposedHelpers.findAndHookMethod(tm, "getSimOperatorName", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    param.result = cachedSimOperatorName ?: cachedOperator ?: "T-Mobile"
                }
            })
        } catch (_: Throwable) {}
        
        // getNetworkOperator (MCC+MNC)
        try {
            XposedHelpers.findAndHookMethod(tm, "getNetworkOperator", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    ensureBridgeLoaded()
                    param.result = cachedSimOperator ?: "310260"
                }
            })
        } catch (_: Throwable) {}
        
        // getSimCountryIso
        try {
            XposedHelpers.findAndHookMethod(tm, "getSimCountryIso", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = "us"
                }
            })
        } catch (_: Throwable) {}
        
        // getNetworkCountryIso
        try {
            XposedHelpers.findAndHookMethod(tm, "getNetworkCountryIso", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = "us"
                }
            })
        } catch (_: Throwable) {}
        
        // getPhoneType (GSM)
        try {
            XposedHelpers.findAndHookMethod(tm, "getPhoneType", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = TelephonyManager.PHONE_TYPE_GSM
                }
            })
        } catch (_: Throwable) {}
        
        // getNetworkType / getDataNetworkType -> LTE
        try {
            XposedHelpers.findAndHookMethod(tm, "getDataNetworkType", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = TelephonyManager.NETWORK_TYPE_LTE
                }
            })
        } catch (_: Throwable) {}
    }
    
    // =========================================================================
    // Display Metrics (Pixel 6: 1080x2400, 411dpi) – Phase 10.0
    // =========================================================================
    
    private fun hookDisplayMetrics() {
        // Hook Display.getMetrics
        try {
            XposedHelpers.findAndHookMethod(
                "android.view.Display", null, "getMetrics",
                DisplayMetrics::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val dm = param.args[0] as? DisplayMetrics ?: return
                        patchDisplayMetrics(dm, false)
                    }
                }
            )
        } catch (_: Throwable) {}
        
        // Hook Display.getRealMetrics
        try {
            XposedHelpers.findAndHookMethod(
                "android.view.Display", null, "getRealMetrics",
                DisplayMetrics::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val dm = param.args[0] as? DisplayMetrics ?: return
                        patchDisplayMetrics(dm, true)
                    }
                }
            )
        } catch (_: Throwable) {}
        
        // Hook Display.getRealSize (deprecated but still used)
        try {
            XposedHelpers.findAndHookMethod(
                "android.view.Display", null, "getRealSize",
                android.graphics.Point::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val point = param.args[0] as? android.graphics.Point ?: return
                        point.x = PIXEL6_WIDTH
                        point.y = PIXEL6_HEIGHT
                    }
                }
            )
        } catch (_: Throwable) {}
        
        // Hook Display.getSize
        try {
            XposedHelpers.findAndHookMethod(
                "android.view.Display", null, "getSize",
                android.graphics.Point::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val point = param.args[0] as? android.graphics.Point ?: return
                        point.x = PIXEL6_WIDTH
                        point.y = PIXEL6_HEIGHT
                    }
                }
            )
        } catch (_: Throwable) {}
        
        log("Display hooks: ${PIXEL6_WIDTH}x${PIXEL6_HEIGHT} @ ${PIXEL6_DENSITY_DPI}dpi")
    }
    
    private fun patchDisplayMetrics(dm: DisplayMetrics, isReal: Boolean) {
        dm.widthPixels = PIXEL6_WIDTH
        dm.heightPixels = PIXEL6_HEIGHT
        dm.densityDpi = PIXEL6_DENSITY_DPI
        dm.density = PIXEL6_DENSITY
        dm.scaledDensity = PIXEL6_SCALED_DENSITY
        dm.xdpi = PIXEL6_XDPI
        dm.ydpi = PIXEL6_YDPI
    }
    
    // =========================================================================
    // Sensor Manager Stealth (Pixel 6 echte Sensoren) – Phase 10.0
    // =========================================================================
    
    private fun hookSensorManager(lpparam: XC_LoadPackage.LoadPackageParam) {
        val sensorManagerClass = XposedHelpers.findClass(
            "android.hardware.SensorManager", lpparam.classLoader
        )
        
        // Hook getSensorList - filtere Virtual/Mock Sensoren raus
        XposedHelpers.findAndHookMethod(
            sensorManagerClass, "getSensorList", Int::class.javaPrimitiveType,
            object : XC_MethodHook() {
                @Suppress("UNCHECKED_CAST")
                override fun afterHookedMethod(param: MethodHookParam) {
                    val sensors = param.result as? List<*> ?: return
                    
                    // Filtere verdächtige Sensoren raus
                    val filtered = sensors.filter { sensor ->
                        if (sensor == null) return@filter false
                        try {
                            val name = XposedHelpers.callMethod(sensor, "getName") as? String ?: ""
                            val vendor = XposedHelpers.callMethod(sensor, "getVendor") as? String ?: ""
                            
                            // Blocke Virtual, Mock, und Debug Sensoren
                            val isVirtual = name.contains("Virtual", ignoreCase = true) ||
                                            name.contains("Mock", ignoreCase = true) ||
                                            name.contains("Emulator", ignoreCase = true) ||
                                            name.contains("Debug", ignoreCase = true) ||
                                            vendor.contains("Virtual", ignoreCase = true) ||
                                            vendor.contains("Mock", ignoreCase = true)
                            !isVirtual
                        } catch (_: Throwable) {
                            true  // Im Zweifel behalten
                        }
                    }
                    
                    if (filtered.size != sensors.size) {
                        param.result = filtered
                        log("SensorManager: Filtered ${sensors.size - filtered.size} virtual sensors (${filtered.size} remain)")
                    }
                }
            }
        )
        
        // Hook Sensor.getName - ersetze verdächtige Namen
        try {
            val sensorClass = XposedHelpers.findClass("android.hardware.Sensor", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(sensorClass, "getVendor", object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val vendor = param.result as? String ?: return
                    if (vendor.contains("AOSP", ignoreCase = true) || 
                        vendor.contains("Virtual", ignoreCase = true)) {
                        param.result = "Bosch"
                    }
                }
            })
        } catch (_: Throwable) {}
        
        // Block Sensor Serial Number (forensischer Fingerprint)
        try {
            val sensorClass = XposedHelpers.findClass("android.hardware.Sensor", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(sensorClass, "getSerialNumber", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = ""  // Keine echte Hardware-Seriennummer preisgeben
                }
            })
            log("Sensor.getSerialNumber() blocked")
        } catch (_: Throwable) {}
    }
    
    // =========================================================================
    // Battery Manager (Realistische Werte mit Ohm'scher Spannungskurve) – Phase 15.0
    // =========================================================================
    
    private fun hookBatteryManager() {
        // Generiere einen pseudo-zufälligen aber stabilen Ladestand pro Session
        val hour = (System.currentTimeMillis() / 3600000) % 24
        val sessionBattery = when {
            hour in 0..5   -> (35..55).random()
            hour in 6..8   -> (70..90).random()
            hour in 9..12  -> (55..80).random()
            hour in 13..17 -> (40..70).random()
            hour in 18..21 -> (25..50).random()
            else           -> (30..60).random()
        }
        
        // Ohm'sche Spannungskurve: V = 3.3 + (level/100) * 0.9
        // 0% -> 3300mV, 50% -> 3750mV, 100% -> 4200mV (LiPo Zelle)
        val sessionVoltage = (3300 + (sessionBattery * 9)).coerceIn(3300, 4200)
        
        // Temperatur: 25-32°C (realistisch für Smartphone im Betrieb)
        // Leicht variierend basierend auf Akkulevel (höher = wärmer beim Laden)
        val sessionTemp = 250 + (sessionBattery / 10) + (0..20).random()
        
        try {
            XposedHelpers.findAndHookMethod(
                BatteryManager::class.java, "getIntProperty", Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        when (param.args[0] as Int) {
                            BatteryManager.BATTERY_PROPERTY_CAPACITY -> param.result = sessionBattery
                            BatteryManager.BATTERY_PROPERTY_STATUS -> {
                                param.result = if (sessionBattery < 90) 
                                    BatteryManager.BATTERY_STATUS_DISCHARGING 
                                else 
                                    BatteryManager.BATTERY_STATUS_FULL
                            }
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
        
        try {
            XposedHelpers.findAndHookMethod(
                "android.content.Intent", null, "getIntExtra",
                String::class.java, Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        when (param.args[0] as? String) {
                            "level" -> param.result = sessionBattery
                            "scale" -> param.result = 100
                            "temperature" -> param.result = sessionTemp
                            "voltage" -> param.result = sessionVoltage  // Ohm'sche Kurve
                            "health" -> param.result = 2                 // BATTERY_HEALTH_GOOD
                            "plugged" -> { if (sessionBattery < 95) param.result = 0 }
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
    }
    
    // =========================================================================
    // Sensor Jitter (Behavioral Biometrics) – Phase 15.0
    // Verhindert statische Sensorwerte, die auf Emulator/Hook hinweisen
    // =========================================================================
    
    private fun hookSensorJitter(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            val listenerClass = XposedHelpers.findClass(
                "android.hardware.SensorEventListener", lpparam.classLoader
            )
            
            // Hook SensorManager.registerListener -> onSensorChanged wird gehookt
            val sensorEventClass = XposedHelpers.findClass(
                "android.hardware.SensorEvent", lpparam.classLoader
            )
            
            // Hooke die interne Dispatching-Methode
            XposedHelpers.findAndHookMethod(
                "android.hardware.SystemSensorManager\$SensorEventQueue",
                lpparam.classLoader,
                "dispatchSensorEvent",
                Int::class.javaPrimitiveType,  // handle
                FloatArray::class.java,         // values
                Int::class.javaPrimitiveType,   // accuracy
                Long::class.javaPrimitiveType,  // timestamp
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val values = param.args[1] as? FloatArray ?: return
                        
                        // Füge minimale Varianz hinzu (0.0001 Jitter)
                        // Nur für Accelerometer/Gyro relevant (3 Achsen)
                        if (values.size >= 3) {
                            for (i in 0 until minOf(values.size, 3)) {
                                // Mikro-Jitter: ±0.0001 (unmerklich, aber nicht statisch)
                                val jitter = ((Math.random() - 0.5) * 0.0002).toFloat()
                                values[i] += jitter
                            }
                            param.args[1] = values
                        }
                    }
                }
            )
            log("SensorJitter: Behavioral biometrics active (±0.0001 variance)")
        } catch (_: Throwable) {}
    }
    
    // =========================================================================
    // Advertising ID (AAID) Hook
    // =========================================================================
    
    private fun hookAdvertisingId(lpparam: XC_LoadPackage.LoadPackageParam) {
        val fakeAaid = generateDeterministicAaid()
        log("AAID: Target value = $fakeAaid")
        
        // --- Methode 1: AdvertisingIdClient.Info.getId() ---
        try {
            val infoClass = XposedHelpers.findClass(
                "com.google.android.gms.ads.identifier.AdvertisingIdClient\$Info",
                lpparam.classLoader
            )
            XposedHelpers.findAndHookMethod(
                infoClass, "getId",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        param.result = fakeAaid
                        log("AAID: Info.getId() spoofed -> $fakeAaid")
                    }
                }
            )
            log("AAID: AdvertisingIdClient.Info.getId() hooked")
        } catch (e: Throwable) {
            log("AAID: Info class not in classloader (expected for non-GMS apps)")
        }
        
        // --- Methode 2: AdvertisingIdClient.getAdvertisingIdInfo() ---
        try {
            val clientClass = XposedHelpers.findClass(
                "com.google.android.gms.ads.identifier.AdvertisingIdClient",
                lpparam.classLoader
            )
            XposedHelpers.findAndHookMethod(
                clientClass, "getAdvertisingIdInfo",
                android.content.Context::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val info = param.result ?: return
                        // Reflection: Versuche alle bekannten Feld-Namen in verschiedenen GMS-Versionen
                        for (fieldName in arrayOf("zzb", "zza", "mId", "advertisingId")) {
                            try {
                                val idField = info.javaClass.getDeclaredField(fieldName)
                                idField.isAccessible = true
                                idField.set(info, fakeAaid)
                                log("AAID: getAdvertisingIdInfo field '$fieldName' spoofed -> $fakeAaid")
                                return
                            } catch (_: Throwable) {}
                        }
                        // Fallback: Versuche alle String-Felder zu patchen
                        try {
                            for (field in info.javaClass.declaredFields) {
                                if (field.type == String::class.java) {
                                    field.isAccessible = true
                                    val current = field.get(info) as? String
                                    if (current != null && current.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))) {
                                        field.set(info, fakeAaid)
                                        log("AAID: Patched UUID-field '${field.name}' -> $fakeAaid")
                                        return
                                    }
                                }
                            }
                        } catch (_: Throwable) {}
                    }
                }
            )
            log("AAID: AdvertisingIdClient.getAdvertisingIdInfo() hooked")
        } catch (e: Throwable) {
            log("AAID: AdvertisingIdClient class not in classloader")
        }
        
        // --- Methode 3: ContentResolver.call (GMS Ads Provider) ---
        try {
            // 4-arg Variante (Android 11+)
            XposedHelpers.findAndHookMethod(
                "android.content.ContentResolver", lpparam.classLoader,
                "call",
                Uri::class.java, String::class.java, String::class.java, android.os.Bundle::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val uri = param.args[0] as? Uri ?: return
                        if (uri.authority?.contains("google.android.gms.ads") != true &&
                            uri.authority?.contains("com.google.android.gms") != true) return
                        
                        val bundle = param.result as? android.os.Bundle ?: return
                        // Suche nach AAID-ähnlichen Keys
                        for (key in arrayOf("ad_id", "advertising_id", "adid", "id")) {
                            val v = bundle.getString(key)
                            if (v != null && v.contains("-")) {
                                bundle.putString(key, fakeAaid)
                                log("AAID: ContentResolver.call key='$key' spoofed -> $fakeAaid")
                            }
                        }
                        param.result = bundle
                    }
                }
            )
            log("AAID: ContentResolver.call(4-arg) hooked")
        } catch (_: Throwable) {}
        
        // --- Methode 4: ContentResolver.call (3-arg Legacy) ---
        try {
            XposedHelpers.findAndHookMethod(
                "android.content.ContentResolver", lpparam.classLoader,
                "call",
                String::class.java, String::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val authority = param.args[0] as? String ?: return
                        if (!authority.contains("google.android.gms")) return
                        
                        val bundle = param.result as? android.os.Bundle ?: return
                        for (key in arrayOf("ad_id", "advertising_id", "adid", "id")) {
                            val v = bundle.getString(key)
                            if (v != null && v.contains("-")) {
                                bundle.putString(key, fakeAaid)
                                log("AAID: ContentResolver.call(3-arg) key='$key' -> $fakeAaid")
                            }
                        }
                        param.result = bundle
                    }
                }
            )
            log("AAID: ContentResolver.call(3-arg) hooked")
        } catch (_: Throwable) {}
        
        // --- Methode 5: IPC via Binder - Fange Intent-basierte AAID Abfragen ab ---
        // Device ID und TikTok nutzen oft android.gms.ads.identifier.service.START
        try {
            XposedHelpers.findAndHookMethod(
                "android.content.Context", lpparam.classLoader,
                "bindService",
                android.content.Intent::class.java,
                android.content.ServiceConnection::class.java,
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val intent = param.args[0] as? android.content.Intent ?: return
                        val action = intent.action ?: return
                        if (action.contains("ads.identifier") || action.contains("advertising_id")) {
                            log("AAID: bindService detected action=$action")
                        }
                    }
                }
            )
        } catch (_: Throwable) {}
    }
    
    /**
     * Generiert eine deterministische AAID basierend auf der Bridge-Identität.
     * Damit ist die AAID pro Identitäts-Profil konsistent, aber unterschiedlich
     * zwischen verschiedenen Profilen.
     */
    private fun generateDeterministicAaid(): String {
        try {
            val seed = "${cachedSerial}-${cachedImei1}-${cachedGsfId}-aaid"
            val md = java.security.MessageDigest.getInstance("SHA-256")
            val hash = md.digest(seed.toByteArray())
            // Format als UUID: 8-4-4-4-12
            val hex = hash.joinToString("") { "%02x".format(it) }
            return "${hex.substring(0,8)}-${hex.substring(8,12)}-4${hex.substring(13,16)}-" +
                   "${(hex.substring(16,17).toInt(16) and 0x3 or 0x8).toString(16)}${hex.substring(17,20)}-" +
                   "${hex.substring(20,32)}"
        } catch (_: Throwable) {
            // Fallback: feste AAID
            return "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
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
    
    // Stealth-Logging: Nur beim Init loggen, nicht bei jedem Hook-Call
    @Volatile private var logCount = 0
    private val MAX_LOG_LINES = 200  // Erhöht für Phase 13 Debugging
    
    private fun log(msg: String) {
        if (logCount >= MAX_LOG_LINES) return
        logCount++
        try { XposedBridge.log("[$TAG] $msg") } catch (_: Throwable) {}
    }
}
