package com.titan.verifier

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader

private const val TAG = "RootShell"

/**
 * Hilfsklasse: Befehle via su ausführen.
 * su -M = Master-Namespace (KernelSU), volle Sicht auf /data, /sys, /persist.
 */
object RootShell {

    @Volatile
    private var rootRetryDone = false

    @Volatile
    private var useSuC = false

    /**
     * Führt Befehl mit su aus. Versucht su -M (Master-Namespace); bei Konsistenz-Fehler Fallback auf su -c.
     */
    fun execute(command: String): String? {
        if (command.isBlank()) return null
        var result = execWithSu(command)
        if (result == null && !rootRetryDone) {
            rootRetryDone = true
            try { Thread.sleep(2500) } catch (_: InterruptedException) {}
            result = execWithSu(command)
        }
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

    /** GSF ID: content query, sqlite3, cat/grep. Reihenfolge nach Erfolgswahrscheinlichkeit. */
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
        val sqliteOut = execute(
            "sqlite3 /data/data/com.google.android.gsf/databases/gservices.db \"select value from main where name='android_id';\" 2>/dev/null"
        )
        if (!sqliteOut.isNullOrBlank() && !sqliteOut.contains("not found") && !sqliteOut.contains("Permission") &&
            !sqliteOut.contains("Error") && !sqliteOut.contains("No such"))
        {
            val raw = sqliteOut.trim()
            if (raw.length in 8..20 && raw.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) return raw
        }
        for (path in GSF_FILES) {
            execute("cat $path")?.let { out ->
                GSF_REGEX.find(out)?.groupValues?.get(1)?.trim()?.let { if (it.length in 8..20) return it }
            }
        }
        execute("grep -rh android_id /data/data/com.google.android.gsf/shared_prefs/ 2>/dev/null")?.let { grepOut ->
            GSF_REGEX.find(grepOut)?.groupValues?.get(1)?.trim()?.let { if (it.length in 8..20) return it }
        }
        return ""
    }

    /** IMEI: service call (s16 für Android 14), dumpsys. */
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
        return ""
    }

    /** Parcel: IMEI zwischen Single-Quotes. cut -d \"'\" -f 2 -s | tr -d '.[:space:]' */
    private fun parseImeiFromOutput(out: String, slot: Int): String {
        val quoted = Regex("'([^']*)'").findAll(out).map { it.groupValues[1] }.toList()
        for (q in quoted) {
            val digits = q.filter { it.isDigit() }
            if (digits.length >= 15) return digits.take(15)
        }
        val ids = IMEI_REGEX.findAll(out).map { it.value }.toList()
        return ids.getOrNull(if (slot == 1) 1 else 0) ?: ids.firstOrNull() ?: ""
    }

    /** Android ID (SSAID) via settings get secure. */
    fun getAndroidIdViaRoot(): String {
        return execute("settings get secure android_id")?.trim() ?: ""
    }

    /** Serial: getprop ro.serialno, Fallback ro.boot.serialno. */
    fun getSerialViaRoot(): String {
        return execute("getprop ro.serialno")?.trim()
            ?: execute("getprop ro.boot.serialno")?.trim()
            ?: ""
    }

    /** Boot Serial (ro.boot.serialno). */
    fun getBootSerialViaRoot(): String {
        return execute("getprop ro.boot.serialno")?.trim() ?: ""
    }

    /** IMSI via dumpsys telephony.registry. */
    fun getImsiViaRoot(): String {
        val out = execute("dumpsys telephony.registry 2>/dev/null") ?: return ""
        val m = Regex("mSubscriberId=([0-9]{10,15})").find(out)
        return m?.groupValues?.get(1) ?: ""
    }

    /** SIM Serial (ICCID) via dumpsys. */
    fun getSimSerialViaRoot(): String {
        val out = execute("dumpsys iphonesubinfo 2>/dev/null") ?: execute("service call iphonesubinfo 5 s16 com.android.shell 2>/dev/null") ?: return ""
        val m = Regex("(?:ICCID|iccId|Sim Serial|simSerial)[^0-9]*([0-9]{10,20})", RegexOption.IGNORE_CASE).find(out)
        return m?.groupValues?.get(1) ?: Regex("\\b([0-9]{18,22})\\b").find(out)?.groupValues?.get(1) ?: ""
    }

    /** MAC: wlan0, eth0, persist, ip link. */
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
        return ""
    }
}
