package com.titan.verifier

import android.content.Context
import android.util.Log
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
 */
object AuditEngine {

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
        if (hasJava && hasNative && j != n) return LayeredStatus.INCONSISTENT
        if (hasJava && hasNative && hasRoot && j == n && j != r) return LayeredStatus.SPOOFED
        if (hasNative && hasRoot && n != r) return LayeredStatus.INCONSISTENT
        return LayeredStatus.CONSISTENT
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

    /** Widevine mit Java MediaDrm Fallback, wenn Native ERROR liefert. */
    fun getWidevineIdWithFallback(context: Context): String {
        val nativeId = getWidevineID()
        if (nativeId.isNotEmpty() && !nativeId.startsWith("ERROR")) return nativeId
        return getWidevineIdJava()
    }

    /** Java MediaDrm Fallback für Widevine Device Unique ID. */
    private fun getWidevineIdJava(): String {
        val widevineUuid = UUID.fromString("ed282e16-fdd2-47c7-8d6d-09946462f367")
        return try {
            MediaDrm(widevineUuid).use { drm ->
                val bytes = drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
                bytes?.let { b ->
                    b.joinToString("") { "%02x".format(it) }
                } ?: ""
            }
        } catch (_: Throwable) {
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

    /** Schreibt Serial in Cache für Zygisk-Hook (TitanHardwareState Bridge). */
    private fun writeSerialToCache(context: Context, serial: String) {
        try {
            File(context.cacheDir, ".titan_serial").writeText(serial)
        } catch (_: Throwable) { /* ignore */ }
    }

    /** Schreibt Boot-Serial in Cache für Zygisk-Hook. */
    private fun writeBootSerialToCache(context: Context, bootSerial: String) {
        try {
            File(context.cacheDir, ".titan_boot_serial").writeText(bootSerial)
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

    /** GSF: Java + Root (Native nicht verfügbar). Root-Fallback bei fehlendem Java. */
    fun getGsfIdLayered(context: Context): LayeredAuditRow {
        var javaV = getGsfIdJava(context)
        val rootV = RootShell.getGsfIdViaRoot()
        if (javaV.isEmpty() && rootV.isNotEmpty()) { /* Root-Fallback bereits in rootValue */ }
        val status = computeLayeredStatus(javaV, "", rootV)
        return LayeredAuditRow(
            label = "GSF ID",
            javaValue = orDash(javaV),
            nativeValue = "—",
            rootValue = orDash(rootV),
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
            javaValue = orDash(javaV),
            nativeValue = "—",
            rootValue = orDash(rootV),
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
        val javaDisplay = r.javaStatusMessage ?: orDash(r.value)
        val status = computeLayeredStatus(r.value, "", rootV)
        return LayeredAuditRow(
            label = "IMEI 1",
            javaValue = javaDisplay,
            nativeValue = "—",
            rootValue = orDash(rootV),
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
        val javaDisplay = r.javaStatusMessage ?: orDash(r.value)
        val status = computeLayeredStatus(r.value, "", rootV)
        return LayeredAuditRow(
            label = "IMEI 2",
            javaValue = javaDisplay,
            nativeValue = "—",
            rootValue = orDash(rootV),
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
}
