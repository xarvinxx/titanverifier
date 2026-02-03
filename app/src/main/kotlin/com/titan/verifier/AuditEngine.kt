package com.titan.verifier

import android.content.Context
import android.net.Uri
import android.provider.Settings
import android.telephony.TelephonyManager
import com.google.android.gms.ads.identifier.AdvertisingIdClient

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

    private fun getImeiJava(context: Context, slot: Int): String {
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager ?: return ""
            if (slot == 0) tm.imei ?: "" else tm.getImei(1) ?: ""
        } catch (_: SecurityException) {
            ""
        } catch (_: Throwable) {
            ""
        }
    }

    /** IMEI Slot 0. Fallback: RootShell service call iphonesubinfo 1. */
    fun getImei1(context: Context): String {
        val j = getImeiJava(context, 0)
        if (j.isNotEmpty()) return j
        return RootShell.getImeiViaRoot(0)
    }

    /** IMEI Slot 1 (Dual SIM). Fallback: RootShell service call iphonesubinfo 2. */
    fun getImei2(context: Context): String {
        val j = getImeiJava(context, 1)
        if (j.isNotEmpty()) return j
        return RootShell.getImeiViaRoot(1)
    }

    /** IMSI (Subscriber ID). READ_PHONE_STATE oder Root-Fallback. */
    fun getImsi(context: Context): String {
        val j = try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            tm?.subscriberId ?: ""
        } catch (_: SecurityException) { "" } catch (_: Throwable) { "" }
        if (j.isNotEmpty()) return j
        return RootShell.getImsiViaRoot()
    }

    /** SIM Serial (ICCID). Java oder Root-Fallback. */
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

    /** IMEI 1: Java + Root. */
    fun getImei1Layered(context: Context): LayeredAuditRow {
        val javaV = getImeiJava(context, 0)
        val rootV = RootShell.getImeiViaRoot(0)
        val status = computeLayeredStatus(javaV, "", rootV)
        return LayeredAuditRow(
            label = "IMEI 1",
            javaValue = orDash(javaV),
            nativeValue = "—",
            rootValue = orDash(rootV),
            isCritical = true,
            status = status
        )
    }

    /** IMEI 2: Java + Root. */
    fun getImei2Layered(context: Context): LayeredAuditRow {
        val javaV = getImeiJava(context, 1)
        val rootV = RootShell.getImeiViaRoot(1)
        val status = computeLayeredStatus(javaV, "", rootV)
        return LayeredAuditRow(
            label = "IMEI 2",
            javaValue = orDash(javaV),
            nativeValue = "—",
            rootValue = orDash(rootV),
            isCritical = false,
            status = status
        )
    }

    /** Serial: Native + Root (Java nicht verfügbar). ROOT_REQUIRED → Root-Fallback. */
    fun getSerialLayered(): LayeredAuditRow {
        var nativeV = getNativeSerialRaw()
        if (nativeV == "ROOT_REQUIRED") nativeV = ""
        val rootV = RootShell.getSerialViaRoot()
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
