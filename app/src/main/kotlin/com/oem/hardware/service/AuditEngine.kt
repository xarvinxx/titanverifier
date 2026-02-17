package com.oem.hardware.service

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.SensorManager
import android.os.BatteryManager
import android.os.Build
import android.util.DisplayMetrics
import android.util.Log
import android.view.WindowManager
import java.io.File
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.media.MediaDrm
import android.net.Uri
import android.provider.Settings
import android.telephony.TelephonyManager
import com.google.android.gms.ads.identifier.AdvertisingIdClient
import java.util.UUID

/**
 * Ground Truth Audit Engine: JNI für Native-IDs, Kotlin für Framework-IDs.
 * Layered Identity: Java | Native | Root mit Status INCONSISTENT / SPOOFED / CONSISTENT.
 * 
 * Verified validation for Zygisk hook checks.
 */
object AuditEngine {

    private const val TAG = "AuditEngine"

    // Bridge paths (app data dir preferred)
    private val BRIDGE_PATHS = arrayOf(
        "/data/data/com.oem.hardware.service/files/.hw_config",
        "/data/user/0/com.oem.hardware.service/files/.hw_config",
        "/data/adb/modules/hw_overlay/.hw_config",
        "/sdcard/.hw_config",
        "/data/local/tmp/.hw_config"
    )

    private fun norm(s: String): String = s.trim()

    private fun computeLayeredStatus(
        javaValue: String,
        nativeValue: String,
        rootValue: String
    ): LayeredStatus {
        val j = norm(javaValue)
        val n = norm(nativeValue)
        val r = norm(rootValue)
        if (j.isEmpty() && n.isEmpty() && r.isEmpty()) return LayeredStatus.MISSING
        val hasJava = j.isNotEmpty()
        val hasNative = n.isNotEmpty()
        val hasRoot = r.isNotEmpty()
        
        // Java und Native widersprechen sich → echtes Problem
        if (hasJava && hasNative && !j.equals(n, ignoreCase = true)) return LayeredStatus.INCONSISTENT
        
        // Hooked-Wert (Java oder Native) ≠ Root → SPOOFED (Hook funktioniert!)
        // Das ist der gewünschte Zustand: Apps sehen den Fake-Wert, Root zeigt den echten
        val hookedValue = if (hasJava) j else if (hasNative) n else ""
        if (hookedValue.isNotEmpty() && hasRoot && !hookedValue.equals(r, ignoreCase = true)) {
            return LayeredStatus.SPOOFED
        }
        
        return LayeredStatus.CONSISTENT
    }
    
    // Verified validation: whether Zygisk hooks were applied successfully
    
    /**
     * Lädt die erwarteten Spoofing-Werte aus der Bridge-Datei.
     * Format: key=value (eine Zeile pro Feld)
     * Durchsucht alle konfigurierten Pfade.
     */
    private fun loadBridgeValues(): Map<String, String> {
        val values = mutableMapOf<String, String>()
        
        // Durchsuche alle Bridge-Pfade
        for (path in BRIDGE_PATHS) {
            try {
                val bridgeFile = java.io.File(path)
                if (bridgeFile.exists() && bridgeFile.canRead()) {
                    bridgeFile.readLines().forEach { line ->
                        val trimmed = line.trim()
                        if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
                        
                        val eqIndex = trimmed.indexOf('=')
                        if (eqIndex > 0) {
                            val key = trimmed.substring(0, eqIndex).trim().lowercase()
                            val value = trimmed.substring(eqIndex + 1).trim()
                            values[key] = value
                        }
                    }
                    
                    if (values.isNotEmpty()) {
                        Log.d(TAG, "Bridge loaded from $path (${values.size} values)")
                        return values
                    }
                }
            } catch (e: Exception) {
                Log.d(TAG, "Bridge path $path: ${e.message}")
            }
        }
        
        Log.w(TAG, "Bridge file not found in any path!")
        return values
    }
    
    /**
     * Validiert ob ein Wert erfolgreich vom Hook überschrieben wurde.
     * @return Pair<Boolean, String> - (isVerified, displayValue)
     *         isVerified = true wenn aktueller Wert == erwarteter Spoofing-Wert
     */
    fun validateHookResult(bridgeKey: String, currentValue: String): HookValidation {
        val bridgeValues = loadBridgeValues()
        val expectedValue = bridgeValues[bridgeKey.lowercase()]
        
        return when {
            expectedValue == null -> {
                // Kein Spoofing-Wert konfiguriert
                HookValidation(
                    isVerified = false,
                    status = HookStatus.NOT_CONFIGURED,
                    displayValue = currentValue,
                    expectedValue = null
                )
            }
            expectedValue.isEmpty() -> {
                HookValidation(
                    isVerified = false,
                    status = HookStatus.EMPTY_CONFIG,
                    displayValue = currentValue,
                    expectedValue = ""
                )
            }
            currentValue.trim() == expectedValue.trim() -> {
                Log.i(TAG, "Verified: $bridgeKey -> $currentValue")
                HookValidation(
                    isVerified = true,
                    status = HookStatus.VERIFIED,
                    displayValue = "[T] $currentValue",
                    expectedValue = expectedValue
                )
            }
            else -> {
                Log.w(TAG, "Mismatch: $bridgeKey expected=$expectedValue actual=$currentValue")
                HookValidation(
                    isVerified = false,
                    status = HookStatus.MISMATCH,
                    displayValue = currentValue,
                    expectedValue = expectedValue
                )
            }
        }
    }
    
    /**
     * Ergebnis einer Hook-Validierung
     */
    data class HookValidation(
        val isVerified: Boolean,
        val status: HookStatus,
        val displayValue: String,
        val expectedValue: String?
    )
    
    enum class HookStatus {
        VERIFIED,        // Hook applied, value matches
        MISMATCH,        // Hook not applied or wrong value
        NOT_CONFIGURED,  // Kein Spoofing für dieses Feld konfiguriert
        EMPTY_CONFIG     // Leerer Wert in Bridge
    }
    
    /**
     * Validiert Serial und gibt [T] Prefix zurück wenn Hook aktiv
     */
    fun getSerialWithValidation(context: Context): Pair<String, Boolean> {
        val serial = getNativeSerial()
        val validation = validateHookResult("serial", serial)
        return Pair(validation.displayValue, validation.isVerified)
    }
    
    /**
     * Validiert alle Felder und gibt eine Zusammenfassung zurück.
     * 
     * 3-Layer-Vergleich:
     * 1. Java-Framework-Wert (aktuelle Abfrage)
     * 2. Native/Root-Wert (systemnahe Abfrage)
     * 3. Bridge-Wert (konfigurierter Spoofing-Wert)
     * 
     * [T] Verified nur wenn: Java == Bridge UND Bridge ist konfiguriert
     */
    fun getValidationSummary(context: Context): ValidationSummary {
        val results = mutableMapOf<String, HookValidation>()
        val bridgeValues = loadBridgeValues()
        
        // === Serial Layer ===
        val serial = getNativeSerial()
        results["serial"] = validate3Layer("serial", serial, serial, bridgeValues)
        
        val bootSerial = getBootSerial()
        results["boot_serial"] = validate3Layer("boot_serial", bootSerial, bootSerial, bridgeValues)
        
        // === IMEI Layer ===
        val imei1Java = getImei1(context)
        val imei1Root = RootShell.getImeiViaRoot(0)
        results["imei1"] = validate3Layer("imei1", imei1Java, imei1Root, bridgeValues)
        
        val imei2Java = getImei2(context)
        val imei2Root = RootShell.getImeiViaRoot(1)
        results["imei2"] = validate3Layer("imei2", imei2Java, imei2Root, bridgeValues)
        
        // === ID Layer ===
        val gsfJava = getGsfIdJava(context)
        val gsfRoot = RootShell.getGsfIdViaRoot()
        results["gsf_id"] = validate3Layer("gsf_id", gsfJava, gsfRoot, bridgeValues)
        
        val androidIdJava = getAndroidId(context)
        val androidIdRoot = RootShell.getAndroidIdViaRoot()
        results["android_id"] = validate3Layer("android_id", androidIdJava, androidIdRoot, bridgeValues)
        
        // === Network Layer ===
        val macNative = getMacAddressWlan0()
        val macRoot = RootShell.getMacWlan0ViaRoot()
        results["wifi_mac"] = validate3Layer("wifi_mac", macNative, macRoot, bridgeValues)
        
        // === SIM Layer ===
        val imsiJava = getImsi(context)
        val imsiRoot = RootShell.getImsiViaRoot()
        results["imsi"] = validate3Layer("imsi", imsiJava, imsiRoot, bridgeValues)
        
        val simSerialJava = getSimSerial(context)
        val simSerialRoot = RootShell.getSimSerialViaRoot()
        results["sim_serial"] = validate3Layer("sim_serial", simSerialJava, simSerialRoot, bridgeValues)
        
        // === DRM Layer ===
        val widevine = getWidevineIdWithFallback(context)
        results["widevine_id"] = validate3Layer("widevine_id", widevine, widevine, bridgeValues)
        
        val verified = results.count { it.value.isVerified }
        val configured = results.count { it.value.status != HookStatus.NOT_CONFIGURED }
        
        Log.i(TAG, "Validation Summary: $verified/$configured verified")
        
        return ValidationSummary(
            results = results,
            verifiedCount = verified,
            configuredCount = configured,
            totalCount = results.size
        )
    }
    
    /**
     * 3-Layer Validierung:
     * Prüft ob Java/Native-Wert mit konfiguriertem Bridge-Wert übereinstimmt.
     * 
     * @param bridgeKey Schlüssel in der Bridge-Datei
     * @param javaValue Wert aus Java-Framework-Abfrage
     * @param rootValue Wert aus Native/Root-Abfrage  
     * @param bridgeValues Alle geladenen Bridge-Werte
     */
    private fun validate3Layer(
        bridgeKey: String, 
        javaValue: String, 
        rootValue: String,
        bridgeValues: Map<String, String>
    ): HookValidation {
        val expectedValue = bridgeValues[bridgeKey.lowercase()]
        val currentValue = javaValue.ifEmpty { rootValue }
        
        return when {
            expectedValue == null -> {
                // Kein Spoofing konfiguriert
                HookValidation(
                    isVerified = false,
                    status = HookStatus.NOT_CONFIGURED,
                    displayValue = currentValue.ifEmpty { "—" },
                    expectedValue = null
                )
            }
            expectedValue.isEmpty() -> {
                HookValidation(
                    isVerified = false,
                    status = HookStatus.EMPTY_CONFIG,
                    displayValue = currentValue.ifEmpty { "—" },
                    expectedValue = ""
                )
            }
            currentValue.trim().equals(expectedValue.trim(), ignoreCase = true) -> {
                Log.i(TAG, "3-Layer VERIFIED: $bridgeKey = $currentValue")
                HookValidation(
                    isVerified = true,
                    status = HookStatus.VERIFIED,
                    displayValue = "[T] $currentValue",
                    expectedValue = expectedValue
                )
            }
            else -> {
                Log.w(TAG, "3-Layer MISMATCH: $bridgeKey expected=$expectedValue actual=$currentValue")
                HookValidation(
                    isVerified = false,
                    status = HookStatus.MISMATCH,
                    displayValue = "⚠ $currentValue",
                    expectedValue = expectedValue
                )
            }
        }
    }
    
    data class ValidationSummary(
        val results: Map<String, HookValidation>,
        val verifiedCount: Int,
        val configuredCount: Int,
        val totalCount: Int
    ) {
        val allVerified: Boolean get() = verifiedCount == configuredCount && configuredCount > 0
        val successRate: Float get() = if (configuredCount > 0) verifiedCount.toFloat() / configuredCount else 0f
        val mismatchCount: Int get() = results.count { it.value.status == HookStatus.MISMATCH }
        
        /**
         * Gibt einen Status-String für die UI zurück.
         */
        fun getStatusText(): String {
            return when {
                allVerified -> "✓ Alle Hooks aktiv ($verifiedCount/$configuredCount)"
                verifiedCount > 0 -> "⚠ Teilweise aktiv ($verifiedCount/$configuredCount)"
                configuredCount == 0 -> "Bridge nicht konfiguriert"
                else -> "✗ Hooks nicht aktiv (0/$configuredCount)"
            }
        }
    }
    
    init {
        System.loadLibrary("native-lib")
    }

    // ─── JNI (Native) ───────────────────────────────────────────────────────

    external fun getNativeProperty(key: String): String
    external fun getWidevineID(): String
    external fun checkRootForensics(): Boolean
    external fun checkRootPath(path: String): Boolean
    external fun getNativeBoard(): String
    external fun getSelinuxEnforce(): Int
    external fun getMacAddressWlan0(): String
    external fun getGpuRenderer(): String
    external fun getInputDeviceList(): String
    external fun getTotalRam(): String

    /** 
     * Widevine: Phase 9.5 - NUR Java API (Ehrlichkeitsmodus).
     * 
     * Nutzt ausschließlich getWidevineIdJava().
     * Native API wird NICHT aufgerufen (Dobby SIGILL Problem).
     * Wenn leer → Auditor zeigt MISSING.
     */
    fun getWidevineIdWithFallback(context: Context): String {
        // NUR Java API (MediaDrm) - LSPosed Hook unterdrückt Konstruktor-Exception
        val javaId = getWidevineIdJava()
        if (javaId.isNotEmpty() && javaId.length >= 16) {
            Log.d(TAG, "[Widevine] Java API -> $javaId")
            return javaId
        }
        
        // KEIN FALLBACK
        Log.e(TAG, "[Widevine] Java API failed - no fallback!")
        return ""
    }

    /** Java MediaDrm für Widevine Device Unique ID (LSPosed hookt diese!). */
    private fun getWidevineIdJava(): String {
        val widevineUuid = UUID.fromString("ed282e16-fdd2-47c7-8d6d-09946462f367")
        return try {
            MediaDrm(widevineUuid).use { drm ->
                val bytes = drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
                bytes?.let { b ->
                    b.joinToString("") { "%02x".format(it) }
                } ?: ""
            }
        } catch (e: Throwable) {
            Log.e(TAG, "[Widevine] Java MediaDrm failed: ${e.message}")
            ""
        }
    }

    /** Synchronisiert GSF-ID und Android-ID in die Native-Ebene. Sofort aufrufen, sobald Werte vorliegen. */
    fun syncIdentityToNative(context: Context) {
        val gsf = getGsfId(context).orEmpty()
        val androidId = getAndroidId(context).orEmpty()
        if (gsf.isNotEmpty() || androidId.isNotEmpty()) {
            NativeEngine.syncIdentity(gsf, androidId)
        }
    }

    fun getBootSerial(): String {
        val n = getNativeProperty("BOOT_SERIAL")
        if (n.isNotEmpty()) return n
        return RootShell.getBootSerialViaRoot()
    }

    /** Native Serial (ro.serialno); liefert ROOT_REQUIRED wenn SELinux blockiert. */
    fun getNativeSerialRaw(): String {
        return getNativeProperty("SERIAL")
    }

    /** Native Serial; bei ROOT_REQUIRED Fallback via RootShell. */
    fun getNativeSerial(): String {
        val s = getNativeSerialRaw()
        if (s == "ROOT_REQUIRED") return RootShell.getSerialViaRoot()
        return s
    }

    /** Writes serial to cache for Zygisk hook (bridge). */
    private fun writeSerialToCache(context: Context, serial: String) {
        try {
            File(context.cacheDir, ".hw_serial").writeText(serial)
        } catch (_: Throwable) { /* ignore */ }
    }

    /** Schreibt Boot-Serial in Cache für Zygisk-Hook. */
    private fun writeBootSerialToCache(context: Context, bootSerial: String) {
        try {
            File(context.cacheDir, ".hw_boot_serial").writeText(bootSerial)
        } catch (_: Throwable) { /* ignore */ }
    }

    /** MAC wlan0; wenn Native leer, Fallback via RootShell. */
    fun getMacAddressWlan0WithFallback(): String {
        val n = getMacAddressWlan0()
        if (n.isNotEmpty()) return n
        return RootShell.getMacWlan0ViaRoot()
    }

    // ─── Framework (Kotlin, benötigt Context) ────────────────────────────────

    /** GSF ID Java-Schicht (content resolver). */
    fun getGsfIdJava(context: Context): String {
        return try {
            val uri = Uri.parse("content://com.google.android.gsf.gservices/id")
            context.contentResolver.query(uri, null, null, arrayOf("android_id"), null)?.use { cursor ->
                if (cursor.moveToFirst() && cursor.columnCount >= 2) {
                    val raw = cursor.getString(1) ?: ""
                    if (raw.length > 1 && raw[0] == '1') raw.drop(1).trim() else raw.trim()
                } else ""
            } ?: ""
        } catch (_: Throwable) {
            ""
        }
    }

    /** GSF ID: Java oder Root-Fallback (content query). */
    fun getGsfId(context: Context): String {
        val j = getGsfIdJava(context)
        if (j.isNotEmpty()) return j
        return RootShell.getGsfIdViaRoot()
    }

    /** Android ID (SSAID): Settings.Secure.ANDROID_ID. */
    fun getAndroidId(context: Context): String {
        return Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: ""
    }

    /**
     * Detaillierter Identity-/Privileged-Status für Debugging (Android 14 Role-Managed Bypass).
     */
    data class DetailedIdentityStatus(
        val isUnderSystemPrivApp: Boolean,
        val packageCodePath: String,
        val permissionProtectionLevel: String,
        val permissionGranted: Boolean
    )

    /**
     * Prüft: Unter /system/priv-app gemountet? Protection-Level der Permission? Grant-Status?
     */
    fun getDetailedIdentityStatus(context: Context): DetailedIdentityStatus {
        val path = try {
            context.packageCodePath ?: ""
        } catch (_: Throwable) {
            ""
        }
        val isUnderPrivApp = path.contains("/system/priv-app", ignoreCase = true)

        val protectionLevel = try {
            val pm = context.packageManager
            val info = pm.getPermissionInfo("android.permission.READ_PRIVILEGED_PHONE_STATE", 0)
            val core = info.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE
            when (core) {
                PermissionInfo.PROTECTION_NORMAL -> "NORMAL"
                PermissionInfo.PROTECTION_DANGEROUS -> "DANGEROUS"
                PermissionInfo.PROTECTION_SIGNATURE -> "SIGNATURE"
                else -> "0x${Integer.toHexString(info.protectionLevel)}"
            }
        } catch (_: Throwable) {
            "unknown"
        }

        val granted = try {
            context.packageManager.checkPermission(
                "android.permission.READ_PRIVILEGED_PHONE_STATE",
                context.packageName
            ) == PackageManager.PERMISSION_GRANTED
        } catch (_: Throwable) {
            false
        }

        // Explizites Logging für automatisierten Grant / Post-Deployment-Verifizierung
        Log.d(
            "AuditEngine",
            "getDetailedIdentityStatus: privApp=$isUnderPrivApp path=$path permLevel=$protectionLevel granted=$granted"
        )

        return DetailedIdentityStatus(
            isUnderSystemPrivApp = isUnderPrivApp,
            packageCodePath = path,
            permissionProtectionLevel = protectionLevel,
            permissionGranted = granted
        )
    }

    /**
     * Prüft, ob die App im privilegierten System-Kontext läuft (z.B. als /system/priv-app).
     * Nutzt ApplicationInfo.FLAG_SYSTEM.
     */
    fun isPrivilegedContext(context: Context): Boolean {
        return try {
            val flags = context.applicationInfo.flags
            val privileged = (flags and ApplicationInfo.FLAG_SYSTEM) != 0
            Log.d("AuditEngine", "isPrivilegedContext: $privileged (FLAG_SYSTEM=${flags and ApplicationInfo.FLAG_SYSTEM})")
            privileged
        } catch (_: SecurityException) {
            Log.w("AuditEngine", "isPrivilegedContext: SecurityException")
            false
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Ergebnis: value = IMEI, javaStatusMessage = Fehlermeldung bei SecurityException (für UI).
     */
    private data class ImeiFetchResult(val value: String, val javaStatusMessage: String?)

    /**
     * IMEI via TelephonyManager. Bei SecurityException: value leer, javaStatusMessage gesetzt.
     */
    private fun getImeiJava(context: Context, slot: Int): ImeiFetchResult {
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager ?: return ImeiFetchResult("", null)
            val v = if (slot == 0) tm.imei ?: "" else tm.getImei(1) ?: ""
            ImeiFetchResult(v, null)
        } catch (e: SecurityException) {
            ImeiFetchResult("", e.message ?: "SecurityException")
        } catch (_: Throwable) {
            ImeiFetchResult("", null)
        }
    }

    /** IMEI Slot 0. Erst Java/API, bei Exception/leer: RootShell + Native-Backdoor setFakeImei. */
    fun getImei1(context: Context): String {
        val r = getImeiJava(context, 0)
        if (r.value.isNotEmpty()) {
            NativeEngine.setFakeImei(r.value)
            return r.value
        }
        val rootV = RootShell.getImeiViaRoot(0)
        if (rootV.isNotEmpty()) NativeEngine.setFakeImei(rootV)
        return rootV
    }

    /** IMEI Slot 1 (Dual SIM). Erst Java/API, bei Exception/leer: RootShell + Native-Backdoor setFakeImei. */
    fun getImei2(context: Context): String {
        val r = getImeiJava(context, 1)
        if (r.value.isNotEmpty()) {
            NativeEngine.setFakeImei(r.value)
            return r.value
        }
        val rootV = RootShell.getImeiViaRoot(1)
        if (rootV.isNotEmpty()) NativeEngine.setFakeImei(rootV)
        return rootV
    }

    /** Native Hook-Memory IMEI (Backdoor-Wert aus C++). */
    fun getNativeHookImei(): String = NativeEngine.getNativeImei()

    /**
     * IMSI (Subscriber ID). Direkter Zugriff via telephonyManager.subscriberId.
     * SecurityException gefangen, falls Privileged-Status fehlt; Fallback RootShell.
     */
    fun getImsi(context: Context): String {
        val j = try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            tm?.subscriberId ?: ""
        } catch (_: SecurityException) { "" } catch (_: Throwable) { "" }
        if (j.isNotEmpty()) return j
        return RootShell.getImsiViaRoot()
    }

    /**
     * SIM Serial (ICCID). Direkter Zugriff via telephonyManager.simSerialNumber.
     * SecurityException gefangen, falls Privileged-Status fehlt; Fallback RootShell.
     */
    fun getSimSerial(context: Context): String {
        val j = try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            tm?.simSerialNumber ?: ""
        } catch (_: SecurityException) { "" } catch (_: Throwable) { "" }
        if (j.isNotEmpty()) return j
        return RootShell.getSimSerialViaRoot()
    }

    /** Advertising ID (AAID) via Google Play Services; leer wenn nicht verfügbar. */
    fun getAdvertisingId(context: Context): String {
        return try {
            AdvertisingIdClient.getAdvertisingIdInfo(context).id ?: ""
        } catch (_: Throwable) {
            ""
        }
    }

    /** Netzbetreiber-Name. */
    fun getOperatorName(context: Context): String {
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            tm?.networkOperatorName ?: ""
        } catch (_: Throwable) {
            ""
        }
    }

    // ─── Layered Identity (Java | Native | Root) ─────────────────────────────

    private fun orDash(s: String): String = if (norm(s).isEmpty()) "—" else s

    /**
     * Zeigt Alternativ-Format an, damit man Werte direkt mit Device ID / anderen Apps vergleichen kann.
     * - Reiner Dezimal-String → zusätzlich Hex (GSF ID, IMEI, etc.)
     * - Reiner Hex-String (kein MAC, keine UUID) → zusätzlich Dezimal + Uppercase (Android ID)
     */
    internal fun withAltFormat(value: String): String {
        val v = value.trim()
        if (v.isEmpty() || v == "—") return v

        // Fall 1: Rein dezimal (z.B. GSF ID "51991968436349795") → Hex anzeigen
        if (v.all { it.isDigit() } && v.length >= 6) {
            val hex = try {
                val num = v.toLongOrNull()
                if (num != null) num.toString(16).uppercase()
                else java.math.BigInteger(v).toString(16).uppercase()
            } catch (_: Throwable) { null }
            return if (!hex.isNullOrEmpty()) "$v\n(hex: $hex)" else v
        }

        // Fall 2: Hex-String ohne Trennzeichen (z.B. Android ID "a6790b84fe007816") → Dezimal + Uppercase
        // Kein MAC (enthält ':' oder '-'), keine UUID (enthält '-'), kein Widevine (32 chars = md5-hash)
        if (v.length in 8..20 && v.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
            && v.any { it in 'a'..'f' || it in 'A'..'F' } // Muss Hex-Chars enthalten
            && !v.contains(':') && !v.contains('-')
        ) {
            val dec = try {
                java.lang.Long.parseUnsignedLong(v, 16).toULong().toString()
            } catch (_: Throwable) {
                try { java.math.BigInteger(v, 16).toString() } catch (_: Throwable) { null }
            }
            val upper = v.uppercase()
            return if (!dec.isNullOrEmpty()) "$upper\n(dec: $dec)" else upper
        }

        return v
    }

    /** GSF: Java + Root (Native nicht verfügbar). Root-Fallback bei fehlendem Java. */
    fun getGsfIdLayered(context: Context): LayeredAuditRow {
        var javaV = getGsfIdJava(context)
        val rootV = RootShell.getGsfIdViaRoot()
        if (javaV.isEmpty() && rootV.isNotEmpty()) { /* Root-Fallback bereits in rootValue */ }
        val status = computeLayeredStatus(javaV, "", rootV)
        return LayeredAuditRow(
            label = "GSF ID",
            javaValue = withAltFormat(orDash(javaV)),
            nativeValue = "—",
            rootValue = withAltFormat(orDash(rootV)),
            isCritical = true,
            status = status
        )
    }

    /** Android ID: Java + Root. */
    fun getAndroidIdLayered(context: Context): LayeredAuditRow {
        val javaV = getAndroidId(context)
        val rootV = RootShell.getAndroidIdViaRoot()
        val status = computeLayeredStatus(javaV, "", rootV)
        return LayeredAuditRow(
            label = "Android ID (SSAID)",
            javaValue = withAltFormat(orDash(javaV)),
            nativeValue = "—",
            rootValue = withAltFormat(orDash(rootV)),
            isCritical = true,
            status = status
        )
    }

    /** IMEI 1: Java + Root. Bei SecurityException: Fehlermeldung im Java-Status, sofort RootShell + setFakeImei. */
    fun getImei1Layered(context: Context): LayeredAuditRow {
        val r = getImeiJava(context, 0)
        val rootV = RootShell.getImeiViaRoot(0)
        val best = r.value.ifEmpty { rootV }
        if (best.isNotEmpty()) NativeEngine.setFakeImei(best)
        val javaRaw = r.value
        val javaDisplay = r.javaStatusMessage ?: withAltFormat(orDash(javaRaw))
        val status = computeLayeredStatus(javaRaw, "", rootV)
        return LayeredAuditRow(
            label = "IMEI 1",
            javaValue = javaDisplay,
            nativeValue = "—",
            rootValue = withAltFormat(orDash(rootV)),
            isCritical = true,
            status = status
        )
    }

    /** IMEI 2: Java + Root. Bei SecurityException: Fehlermeldung im Java-Status, sofort RootShell + setFakeImei. */
    fun getImei2Layered(context: Context): LayeredAuditRow {
        val r = getImeiJava(context, 1)
        val rootV = RootShell.getImeiViaRoot(1)
        val best = r.value.ifEmpty { rootV }
        if (best.isNotEmpty()) NativeEngine.setFakeImei(best)
        val javaRaw = r.value
        val javaDisplay = r.javaStatusMessage ?: withAltFormat(orDash(javaRaw))
        val status = computeLayeredStatus(javaRaw, "", rootV)
        return LayeredAuditRow(
            label = "IMEI 2",
            javaValue = javaDisplay,
            nativeValue = "—",
            rootValue = withAltFormat(orDash(rootV)),
            isCritical = false,
            status = status
        )
    }

    /** Serial: Native + Root (Java nicht verfügbar). ROOT_REQUIRED → Root-Fallback. Zygisk-Bridge: Root-Wert in Cache. */
    fun getSerialLayered(context: Context): LayeredAuditRow {
        var nativeV = getNativeSerialRaw()
        if (nativeV == "ROOT_REQUIRED") nativeV = ""
        val rootV = RootShell.getSerialViaRoot()
        if (rootV.isNotEmpty()) writeSerialToCache(context, rootV)
        val bootV = RootShell.getBootSerialViaRoot()
        if (bootV.isNotEmpty()) writeBootSerialToCache(context, bootV)
        val status = computeLayeredStatus("", nativeV, rootV)
        return LayeredAuditRow(
            label = "Serial (ro.serialno)",
            javaValue = "—",
            nativeValue = orDash(nativeV),
            rootValue = orDash(rootV),
            isCritical = true,
            status = status
        )
    }

    /** MAC wlan0: Native + Root. */
    fun getMacWlan0Layered(): LayeredAuditRow {
        val nativeV = getMacAddressWlan0()
        val rootV = RootShell.getMacWlan0ViaRoot()
        val status = computeLayeredStatus("", nativeV, rootV)
        return LayeredAuditRow(
            label = "MAC (wlan0)",
            javaValue = "—",
            nativeValue = orDash(nativeV),
            rootValue = orDash(rootV),
            isCritical = false,
            status = status
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 10.0 - Full Spectrum Audit Functions
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Battery-Status: Liest den gehookten Ladestand und Temperatur.
     * TikTok nutzt konstante 100% als Emulator-Indikator.
     */
    data class BatteryAudit(
        val level: Int,
        val temperature: Float,
        val voltage: Int,
        val health: String,
        val isCharging: Boolean,
        val isRealistic: Boolean  // true wenn Level != 100 und Temp realistisch
    )
    
    fun getBatteryStatus(context: Context): BatteryAudit {
        return try {
            val batteryStatus: Intent? = IntentFilter(Intent.ACTION_BATTERY_CHANGED).let { filter ->
                context.registerReceiver(null, filter)
            }
            val level = batteryStatus?.getIntExtra("level", -1) ?: -1
            val scale = batteryStatus?.getIntExtra("scale", 100) ?: 100
            val percent = if (scale > 0) (level * 100) / scale else level
            val tempRaw = batteryStatus?.getIntExtra("temperature", -1) ?: -1
            val tempC = tempRaw / 10.0f
            val voltage = batteryStatus?.getIntExtra("voltage", -1) ?: -1
            val healthInt = batteryStatus?.getIntExtra("health", -1) ?: -1
            val healthStr = when (healthInt) {
                BatteryManager.BATTERY_HEALTH_GOOD -> "Good"
                BatteryManager.BATTERY_HEALTH_OVERHEAT -> "Overheat"
                BatteryManager.BATTERY_HEALTH_DEAD -> "Dead"
                BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "Over Voltage"
                BatteryManager.BATTERY_HEALTH_COLD -> "Cold"
                else -> "Unknown ($healthInt)"
            }
            val plugged = batteryStatus?.getIntExtra("plugged", 0) ?: 0
            val isCharging = plugged != 0
            
            // Realistisch = nicht konstant 100%, Temperatur zwischen 15-45°C
            val isRealistic = percent in 1..99 && tempC in 15.0f..45.0f
            
            BatteryAudit(percent, tempC, voltage, healthStr, isCharging, isRealistic)
        } catch (e: Throwable) {
            Log.e(TAG, "getBatteryStatus failed: ${e.message}")
            BatteryAudit(-1, -1f, -1, "Error", false, false)
        }
    }
    
    /**
     * Build Property Stichproben-Audit.
     * Prüft 8 kritische Properties auf Pixel 6 Konsistenz.
     */
    data class BuildPropAudit(
        val properties: Map<String, String>,
        val isConsistent: Boolean,
        val mismatchCount: Int
    )
    
    fun getBuildPropertyAudit(): BuildPropAudit {
        val expected = mapOf(
            "Build.MANUFACTURER" to "Google",
            "Build.MODEL" to "Pixel 6",
            "Build.BRAND" to "google",
            "Build.DEVICE" to "oriole",
            "Build.BOARD" to "oriole",
            "Build.HARDWARE" to "oriole",
            "Build.FINGERPRINT" to "google/oriole/oriole:14/AP1A.240505.004/11583682:user/release-keys",
            "Build.DISPLAY" to "AP1A.240505.004"
        )
        
        val actual = mapOf(
            "Build.MANUFACTURER" to Build.MANUFACTURER,
            "Build.MODEL" to Build.MODEL,
            "Build.BRAND" to Build.BRAND,
            "Build.DEVICE" to Build.DEVICE,
            "Build.BOARD" to Build.BOARD,
            "Build.HARDWARE" to Build.HARDWARE,
            "Build.FINGERPRINT" to Build.FINGERPRINT,
            "Build.DISPLAY" to Build.DISPLAY
        )
        
        var mismatches = 0
        val results = mutableMapOf<String, String>()
        
        for ((key, expectedVal) in expected) {
            val actualVal = actual[key] ?: "—"
            val match = actualVal.equals(expectedVal, ignoreCase = false)
            if (!match) mismatches++
            results[key] = if (match) "[T] $actualVal" else "⚠ $actualVal (expected: $expectedVal)"
        }
        
        return BuildPropAudit(results, mismatches == 0, mismatches)
    }
    
    /**
     * Display Metrics Audit.
     * Pixel 6: 1080x2400 @ 411dpi
     */
    data class DisplayAudit(
        val width: Int,
        val height: Int,
        val densityDpi: Int,
        val density: Float,
        val isPixel6: Boolean
    )
    
    fun getDisplayAudit(context: Context): DisplayAudit {
        return try {
            val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val dm = DisplayMetrics()
            wm.defaultDisplay.getRealMetrics(dm)
            val isPixel6 = dm.widthPixels == 1080 && dm.heightPixels == 2400 && dm.densityDpi == 411
            DisplayAudit(dm.widthPixels, dm.heightPixels, dm.densityDpi, dm.density, isPixel6)
        } catch (e: Throwable) {
            DisplayAudit(0, 0, 0, 0f, false)
        }
    }
    
    /**
     * Sensor List Audit.
     * Prüft ob verdächtige Virtual/Mock Sensoren vorhanden sind.
     */
    data class SensorAudit(
        val totalCount: Int,
        val sensorNames: List<String>,
        val hasVirtual: Boolean,
        val hasMock: Boolean
    )
    
    fun getSensorAudit(context: Context): SensorAudit {
        return try {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            val allSensors = sm.getSensorList(android.hardware.Sensor.TYPE_ALL)
            val names = allSensors.map { "${it.name} (${it.vendor})" }
            val hasVirtual = allSensors.any { 
                it.name.contains("Virtual", true) || it.name.contains("Emulator", true) 
            }
            val hasMock = allSensors.any { 
                it.name.contains("Mock", true) || it.vendor.contains("Mock", true) 
            }
            SensorAudit(allSensors.size, names, hasVirtual, hasMock)
        } catch (e: Throwable) {
            SensorAudit(0, emptyList(), false, false)
        }
    }
    
    /**
     * Telephony Extended Audit.
     * Prüft die neuen Phase 10.0 Felder.
     */
    data class TelephonyAudit(
        val phoneNumber: String,
        val simOperator: String,
        val simOperatorName: String,
        val networkOperator: String,
        val simCountryIso: String,
        val phoneType: String,
        val networkType: String
    )
    
    fun getTelephonyAudit(context: Context): TelephonyAudit {
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            val phoneNumber = try { tm?.line1Number ?: "" } catch (_: SecurityException) { "—" }
            val simOp = tm?.simOperator ?: ""
            val simOpName = tm?.simOperatorName ?: ""
            val netOp = tm?.networkOperator ?: ""
            val simCountry = tm?.simCountryIso ?: ""
            val phoneType = when (tm?.phoneType) {
                TelephonyManager.PHONE_TYPE_GSM -> "GSM"
                TelephonyManager.PHONE_TYPE_CDMA -> "CDMA"
                TelephonyManager.PHONE_TYPE_SIP -> "SIP"
                else -> "NONE"
            }
            val netType = try {
                when (tm?.dataNetworkType) {
                    TelephonyManager.NETWORK_TYPE_LTE -> "LTE"
                    TelephonyManager.NETWORK_TYPE_NR -> "5G NR"
                    TelephonyManager.NETWORK_TYPE_HSDPA -> "HSDPA"
                    TelephonyManager.NETWORK_TYPE_UMTS -> "UMTS"
                    TelephonyManager.NETWORK_TYPE_EDGE -> "EDGE"
                    TelephonyManager.NETWORK_TYPE_GPRS -> "GPRS"
                    else -> "Unknown"
                }
            } catch (_: SecurityException) { "—" }
            
            TelephonyAudit(phoneNumber, simOp, simOpName, netOp, simCountry, phoneType, netType)
        } catch (e: Throwable) {
            TelephonyAudit("", "", "", "", "", "", "")
        }
    }
    
    /**
     * Input Devices Check via Java API (InputManager).
     * Ergänzt den nativen /proc/bus/input/devices Check.
     */
    fun getInputDevicesJava(context: Context): String {
        return try {
            val im = context.getSystemService(Context.INPUT_SERVICE) as? android.hardware.input.InputManager
                ?: return "InputManager unavailable"
            val ids = im.inputDeviceIds
            if (ids.isEmpty()) return "No devices"
            val devices = ids.toList().mapNotNull { id ->
                im.getInputDevice(id)?.let { dev ->
                    "${dev.name} (src=0x${Integer.toHexString(dev.sources)})"
                }
            }
            devices.joinToString(", ")
        } catch (e: Throwable) {
            "Error: ${e.message}"
        }
    }
    
    /**
     * Package Stealth Check: Kann sich die App selbst im PackageManager sehen?
     * Und sieht sie verdächtige Packages (Magisk, KSU, LSPosed)?
     */
    data class StealthAudit(
        val selfVisible: Boolean,
        val suspiciousPackages: List<String>
    )
    
    fun getStealthAudit(context: Context): StealthAudit {
        val suspicious = mutableListOf<String>()
        val pm = context.packageManager
        
        val selfVisible = try {
            pm.getPackageInfo(context.packageName, 0)
            true
        } catch (_: Throwable) { false }
        
        val suspiciousPkgs = listOf(
            "com.topjohnwu.magisk",
            "io.github.vvb2060.magisk",
            "me.weishu.kernelsu",
            "org.lsposed.manager",
            "org.meowcat.edxposed.manager",
            "com.tsng.hidemyapplist"
        )
        for (pkg in suspiciousPkgs) {
            try {
                pm.getPackageInfo(pkg, 0)
                suspicious.add(pkg)
            } catch (_: Throwable) { /* not installed */ }
        }
        
        return StealthAudit(selfVisible, suspicious)
    }
    
    /**
     * Bridge Identity Profile Name.
     * Liest den Identity-Fingerprint aus der Bridge.
     */
    fun getIdentityProfile(): String {
        val bridge = loadBridgeValues()
        if (bridge.isEmpty()) return "Not configured"
        val serial = bridge["serial"] ?: "?"
        val operator = bridge["operator_name"] ?: bridge["sim_operator_name"] ?: "?"
        val mac = bridge["wifi_mac"] ?: "?"
        return "$serial / $operator / ${mac.takeLast(8)}"
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 15.0 - Universal Consistency Check
    // Vergleicht Java-API-Werte mit Native-Werten und Bridge-Erwartungen
    // ═══════════════════════════════════════════════════════════════════════════
    
    data class ConsistencyItem(
        val label: String,
        val javaValue: String,
        val nativeValue: String,
        val isConsistent: Boolean
    )
    
    data class ConsistencyResult(
        val items: List<ConsistencyItem>,
        val totalChecks: Int,
        val consistentCount: Int,
        val inconsistentCount: Int
    )
    
    /**
     * Vergleicht Java-Framework-Werte mit Native-Property-Werten.
     * Jede Diskrepanz wird als INCONSISTENT gemeldet.
     */
    fun checkConsistency(context: Context): ConsistencyResult {
        val items = mutableListOf<ConsistencyItem>()
        
        // 1. Build.MODEL vs ro.product.model
        val javaModel = Build.MODEL
        val nativeModel = getNativeProp("ro.product.model")
        items.add(ConsistencyItem("Build.MODEL", javaModel, nativeModel, 
            javaModel == nativeModel || nativeModel.isEmpty()))
        
        // 2. Build.MANUFACTURER vs ro.product.manufacturer
        val javaMfr = Build.MANUFACTURER
        val nativeMfr = getNativeProp("ro.product.manufacturer")
        items.add(ConsistencyItem("Build.MANUFACTURER", javaMfr, nativeMfr,
            javaMfr == nativeMfr || nativeMfr.isEmpty()))
        
        // 3. Build.BRAND vs ro.product.brand
        val javaBrand = Build.BRAND
        val nativeBrand = getNativeProp("ro.product.brand")
        items.add(ConsistencyItem("Build.BRAND", javaBrand, nativeBrand,
            javaBrand == nativeBrand || nativeBrand.isEmpty()))
        
        // 4. Build.DEVICE vs ro.product.device
        val javaDevice = Build.DEVICE
        val nativeDevice = getNativeProp("ro.product.device")
        items.add(ConsistencyItem("Build.DEVICE", javaDevice, nativeDevice,
            javaDevice == nativeDevice || nativeDevice.isEmpty()))
        
        // 5. Build.FINGERPRINT vs ro.build.fingerprint
        val javaFp = Build.FINGERPRINT
        val nativeFp = getNativeProp("ro.build.fingerprint")
        items.add(ConsistencyItem("Build.FINGERPRINT", javaFp, nativeFp,
            javaFp == nativeFp || nativeFp.isEmpty()))
        
        // 6. Build.BOARD vs ro.product.board
        val javaBoard = Build.BOARD
        val nativeBoard = getNativeProp("ro.product.board")
        items.add(ConsistencyItem("Build.BOARD", javaBoard, nativeBoard,
            javaBoard == nativeBoard || nativeBoard.isEmpty()))
        
        // 7. Build.HARDWARE vs ro.hardware
        val javaHw = Build.HARDWARE
        val nativeHw = getNativeProp("ro.hardware")
        items.add(ConsistencyItem("Build.HARDWARE", javaHw, nativeHw,
            javaHw == nativeHw || nativeHw.isEmpty()))
        
        // 8. Build.DISPLAY vs ro.build.display.id
        val javaDisplay = Build.DISPLAY
        val nativeDisplay = getNativeProp("ro.build.display.id")
        items.add(ConsistencyItem("Build.DISPLAY", javaDisplay, nativeDisplay,
            javaDisplay == nativeDisplay || nativeDisplay.isEmpty()))
        
        // 9. Build.VERSION.SECURITY_PATCH vs ro.build.version.security_patch
        val javaPatch = Build.VERSION.SECURITY_PATCH
        val nativePatch = getNativeProp("ro.build.version.security_patch")
        items.add(ConsistencyItem("VERSION.SECURITY_PATCH", javaPatch, nativePatch,
            javaPatch == nativePatch || nativePatch.isEmpty()))
        
        // 10. Build.VERSION.RELEASE vs ro.build.version.release
        val javaRelease = Build.VERSION.RELEASE
        val nativeRelease = getNativeProp("ro.build.version.release")
        items.add(ConsistencyItem("VERSION.RELEASE", javaRelease, nativeRelease,
            javaRelease == nativeRelease || nativeRelease.isEmpty()))
        
        // 11. Serial: Build.getSerial() vs Native ro.serialno
        val javaSerial = try { Build.getSerial() } catch (_: Throwable) { "" }
        val nativeSerial = getNativeSerial()
        items.add(ConsistencyItem("Serial", javaSerial, nativeSerial,
            javaSerial == nativeSerial || javaSerial.isEmpty() || nativeSerial.isEmpty()))
        
        // 12. WiFi MAC: Java WifiInfo vs Native
        val javaMac = getJavaMacAddress(context)
        val nativeMac = getMacAddressWlan0()
        items.add(ConsistencyItem("WiFi MAC", javaMac, nativeMac,
            javaMac == nativeMac || javaMac.isEmpty() || nativeMac.isEmpty()))
        
        // 13. CPU-Info: /proc/cpuinfo Hardware field
        val cpuHardware = getCpuHardware()
        val expectedCpu = "GS101 Oriole"
        items.add(ConsistencyItem("/proc/cpuinfo Hardware", cpuHardware, expectedCpu,
            cpuHardware.contains("GS101") || cpuHardware.isEmpty()))
        
        // 14. Kernel Version: /proc/version
        val kernelVersion = getKernelVersion()
        items.add(ConsistencyItem("/proc/version", 
            if (kernelVersion.length > 40) kernelVersion.take(40) + "..." else kernelVersion,
            "gs101-based",
            kernelVersion.contains("android") || kernelVersion.isEmpty()))
        
        val consistent = items.count { it.isConsistent }
        val inconsistent = items.count { !it.isConsistent }
        
        return ConsistencyResult(items, items.size, consistent, inconsistent)
    }
    
    /**
     * Liest eine System-Property über den Java-Reflection-Weg.
     */
    private fun getNativeProp(key: String): String {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            method.invoke(null, key) as? String ?: ""
        } catch (_: Throwable) { "" }
    }
    
    /**
     * Liest die MAC-Adresse über die Java WiFi API.
     */
    private fun getJavaMacAddress(context: Context): String {
        return try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE)
            if (wifiManager != null) {
                val wifiInfo = wifiManager.javaClass.getMethod("getConnectionInfo").invoke(wifiManager)
                val mac = wifiInfo?.javaClass?.getMethod("getMacAddress")?.invoke(wifiInfo) as? String
                if (mac != null && mac != "02:00:00:00:00:00") mac else ""
            } else ""
        } catch (_: Throwable) { "" }
    }
    
    /**
     * Liest /proc/cpuinfo Hardware-Zeile.
     */
    private fun getCpuHardware(): String {
        return try {
            val lines = File("/proc/cpuinfo").readLines()
            val hwLine = lines.firstOrNull { it.startsWith("Hardware") }
            hwLine?.substringAfter(":")?.trim() ?: ""
        } catch (_: Throwable) { "" }
    }
    
    /**
     * Liest /proc/version.
     */
    private fun getKernelVersion(): String {
        return try {
            File("/proc/version").readText().trim()
        } catch (_: Throwable) { "" }
    }
}
