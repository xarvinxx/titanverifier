package com.titan.verifier

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.File

private const val TAG = "RootShell"

/**
 * Hilfsklasse: Befehle via su ausführen.
 * su -M = Master-Namespace (KernelSU), volle Sicht auf /data, /sys, /persist.
 * 
 * Phase 11.0: Fallback auf Snapshot-Datei wenn su nicht verfügbar ist
 * (z.B. wenn KernelSU der App keinen Root gewährt hat).
 * Die Snapshot-Datei wird vom Host-Deployment erstellt und enthält
 * die echten (ungehookten) Gerätewerte.
 */
object RootShell {

    @Volatile
    private var rootRetryDone = false

    @Volatile
    private var useSuC = false
    
    @Volatile
    private var suAvailable: Boolean? = null  // null = nicht geprüft
    
    /**
     * Real-Values Snapshot: Wird vom Host-Deployment erstellt.
     * Enthält die echten Gerätewerte im Format key=value.
     */
    private val SNAPSHOT_PATHS = arrayOf(
        "/data/data/com.titan.verifier/files/.titan_real_values",
        "/data/user/0/com.titan.verifier/files/.titan_real_values"
    )
    
    @Volatile
    private var snapshotCache: Map<String, String>? = null
    
    private fun loadSnapshot(): Map<String, String> {
        snapshotCache?.let { return it }
        val values = mutableMapOf<String, String>()
        for (path in SNAPSHOT_PATHS) {
            try {
                val file = File(path)
                if (file.exists() && file.canRead()) {
                    file.readLines().forEach { line ->
                        val trimmed = line.trim()
                        if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
                        val eqIndex = trimmed.indexOf('=')
                        if (eqIndex > 0) {
                            val key = trimmed.substring(0, eqIndex).trim().lowercase()
                            val value = trimmed.substring(eqIndex + 1).trim()
                            if (value.isNotEmpty()) values[key] = value
                        }
                    }
                    if (values.isNotEmpty()) {
                        Log.i(TAG, "Snapshot loaded from $path (${values.size} values)")
                        snapshotCache = values
                        return values
                    }
                }
            } catch (_: Throwable) {}
        }
        Log.w(TAG, "No snapshot file found")
        snapshotCache = values
        return values
    }
    
    /**
     * Liest einen Wert aus dem Snapshot.
     * Wird als Fallback verwendet wenn su nicht verfügbar ist.
     */
    fun getSnapshotValue(key: String): String {
        return loadSnapshot()[key.lowercase()] ?: ""
    }

    /**
     * Führt Befehl mit su aus. Versucht su -M (Master-Namespace); bei Konsistenz-Fehler Fallback auf su -c.
     */
    fun execute(command: String): String? {
        if (command.isBlank()) return null
        // Schneller Bail-out wenn su definitiv nicht funktioniert
        if (suAvailable == false) return null
        
        var result = execWithSu(command)
        if (result == null && !rootRetryDone) {
            rootRetryDone = true
            try { Thread.sleep(2500) } catch (_: InterruptedException) {}
            result = execWithSu(command)
            if (result == null) {
                suAvailable = false
                Log.w(TAG, "su permanently unavailable - using snapshot fallback")
            }
        }
        if (result != null) suAvailable = true
        return result
    }

    private fun execWithSu(command: String): String? {
        val result = if (useSuC) {
            runProcess(arrayOf("su", "-c", command))
        } else {
            runProcess(arrayOf("su", "-M", "-c", command))
                ?: run {
                    Log.w(TAG, "su -M returned null, fallback to su -c")
                    useSuC = true
                    runProcess(arrayOf("su", "-c", command))
                }
        }
        return result
    }

    /**
     * Umgehung "managed by role" (Android 14): cmd permissionmgr statt pm grant.
     * Gibt true zurück, wenn der Befehl erfolgreich ausgeführt wurde.
     */
    fun forceGrantPrivilegedPermission(): Boolean {
        val perm = "android.permission.READ_PRIVILEGED_PHONE_STATE"
        val pkg = "com.titan.verifier"
        val cmd1 = "cmd permissionmgr grant-runtime-permission $pkg $perm"
        val out1 = execute(cmd1)
        if (out1 != null && !out1.lowercase().contains("error") && !out1.lowercase().contains("denied") && !out1.lowercase().contains("managed by role")) return true
        val cmd2 = "cmd permission grant-runtime-permission $pkg $perm"
        val out2 = execute(cmd2)
        if (out2 != null && !out2.lowercase().contains("error") && !out2.lowercase().contains("denied")) return true
        val cmd3 = "pm grant $pkg $perm"
        val out3 = execute(cmd3)
        return out3 != null && !out3.lowercase().contains("managed by role") && !out3.lowercase().contains("error")
    }

    private fun runProcess(args: Array<String>): String? {
        return try {
            val process = Runtime.getRuntime().exec(args)
            val stdout = BufferedReader(InputStreamReader(process.inputStream)).readText().trim()
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).readText().trim()
            process.waitFor()
            if (stderr.isNotEmpty()) Log.w(TAG, "stderr present (masked)")
            if (stdout.isNotEmpty()) stdout else null
        } catch (_: Throwable) {
            Log.w(TAG, "execute failed")
            null
        }
    }

    private val IMEI_REGEX = Regex("\\b\\d{15}\\b")

    private val GSF_REGEX = Regex("android_id[\"\\s=>]*([0-9a-fA-F]{8,20})")
    private val GSF_FILES = listOf(
        "/data/data/com.google.android.gsf/shared_prefs/gls.xml",
        "/data/data/com.google.android.gsf/shared_prefs/Checkin.xml",
        "/data/data/com.google.android.gsf/shared_prefs/checkin_preferences.xml",
        "/data/data/com.google.android.gms/shared_prefs/Checkin.xml"
    )

    /** Parcel: IMEI zwischen Single-Quotes. */
    private fun parseImeiFromOutput(out: String, slot: Int): String {
        val quoted = Regex("'([^']*)'").findAll(out).map { it.groupValues[1] }.toList()
        for (q in quoted) {
            val digits = q.filter { it.isDigit() }
            if (digits.length >= 15) return digits.take(15)
        }
        val ids = IMEI_REGEX.findAll(out).map { it.value }.toList()
        return ids.getOrNull(if (slot == 1) 1 else 0) ?: ids.firstOrNull() ?: ""
    }

    /** Android ID (SSAID) via settings get secure. Snapshot-Fallback. */
    fun getAndroidIdViaRoot(): String {
        val su = execute("settings get secure android_id")?.trim()
        if (!su.isNullOrEmpty()) return su
        return getSnapshotValue("android_id")
    }

    /** Serial: getprop ro.serialno, Fallback ro.boot.serialno. Snapshot-Fallback. */
    fun getSerialViaRoot(): String {
        val su = execute("getprop ro.serialno")?.trim()
            ?: execute("getprop ro.boot.serialno")?.trim()
        if (!su.isNullOrEmpty()) return su
        return getSnapshotValue("serial")
    }

    /** Boot Serial (ro.boot.serialno). Snapshot-Fallback. */
    fun getBootSerialViaRoot(): String {
        val su = execute("getprop ro.boot.serialno")?.trim()
        if (!su.isNullOrEmpty()) return su
        return getSnapshotValue("boot_serial")
    }

    /** IMSI via dumpsys telephony.registry. Snapshot-Fallback. */
    fun getImsiViaRoot(): String {
        val out = execute("dumpsys telephony.registry 2>/dev/null")
        if (out != null) {
            val m = Regex("mSubscriberId=([0-9]{10,15})").find(out)
            if (m != null) return m.groupValues[1]
        }
        return getSnapshotValue("imsi")
    }

    /** SIM Serial (ICCID) via dumpsys. Snapshot-Fallback. */
    fun getSimSerialViaRoot(): String {
        val out = execute("dumpsys iphonesubinfo 2>/dev/null") ?: execute("service call iphonesubinfo 5 s16 com.android.shell 2>/dev/null")
        if (out != null) {
            val m = Regex("(?:ICCID|iccId|Sim Serial|simSerial)[^0-9]*([0-9]{10,20})", RegexOption.IGNORE_CASE).find(out)
            if (m != null) return m.groupValues[1]
            val m2 = Regex("\\b([0-9]{18,22})\\b").find(out)
            if (m2 != null) return m2.groupValues[1]
        }
        return getSnapshotValue("sim_serial")
    }

    /** IMEI via su. Snapshot-Fallback. */
    fun getImeiViaRoot(slot: Int): String {
        val codes = if (slot == 1) listOf(2, 3) else listOf(1, 2)
        val pkgs = listOf("com.android.shell", "com.titan.verifier", "")
        for (code in codes) {
            for (pkg in pkgs) {
                val cmd = if (pkg.isEmpty()) "service call iphonesubinfo $code" else "service call iphonesubinfo $code s16 $pkg"
                execute(cmd)?.let { parseImeiFromOutput(it, slot).takeIf { id -> id.isNotEmpty() }?.let { return it } }
            }
        }
        execute("dumpsys iphonesubinfo")?.let { parseImeiFromOutput(it, slot).takeIf { it.isNotEmpty() }?.let { return it } }
        // Snapshot-Fallback
        return getSnapshotValue(if (slot == 1) "imei2" else "imei1")
    }

    /** GSF ID via root. Snapshot-Fallback. */
    fun getGsfIdViaRoot(): String {
        for (uri in listOf(
            "content://com.google.android.gsf.gservices/id",
            "content://com.google.android.gsf.gservices"
        )) {
            execute("content query --uri $uri 2>/dev/null")?.let { contentOut ->
                GSF_REGEX.find(contentOut)?.groupValues?.get(1)?.trim()?.let { id ->
                    if (id.length in 8..20) return id
                }
                Regex("value=([0-9a-fA-F]{8,20})").find(contentOut)?.groupValues?.get(1)?.let { id ->
                    if (id.length in 8..20) return id
                }
            }
        }
        for (path in GSF_FILES) {
            execute("cat $path")?.let { out ->
                GSF_REGEX.find(out)?.groupValues?.get(1)?.trim()?.let { if (it.length in 8..20) return it }
            }
        }
        // Snapshot-Fallback
        return getSnapshotValue("gsf_id")
    }

    /** MAC: wlan0, eth0, persist, ip link. Snapshot-Fallback. */
    fun getMacWlan0ViaRoot(): String {
        val paths = listOf(
            "/sys/class/net/wlan0/address",
            "/sys/class/net/eth0/address",
            "/persist/wifi/.macaddr",
            "/data/vendor/wifi/mac_addr",
            "/efs/wifi/.mac.info"
        )
        for (p in paths) {
            execute("cat $p 2>/dev/null")?.trim()?.let { mac ->
                if (mac.length in 12..17 && Regex("^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$").matches(mac)) return mac
                if (mac.length == 12 && mac.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
                    return mac.chunked(2).joinToString(":")
                }
            }
        }
        execute("ip link show wlan0 2>/dev/null")?.let { out ->
            Regex("link/ether ([0-9a-f:]{17})").find(out)?.groupValues?.get(1)?.let { return it }
        }
        // Snapshot-Fallback
        return getSnapshotValue("wifi_mac")
    }
}
