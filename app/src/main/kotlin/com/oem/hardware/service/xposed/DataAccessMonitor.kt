package com.oem.hardware.service.xposed

import android.os.Process
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Monitors and logs every data access attempt by target apps.
 *
 * Per-process JSON output to support multi-process tracking:
 *   /data/data/<pkg>/files/.titan_access_summary_<process>.json
 *   /data/data/<pkg>/files/.titan_access_<process>.log
 *
 * Thread-safe, minimal overhead per hook call (~0.1ms).
 */
object DataAccessMonitor {

    private const val MAX_LOG_LINES = 5000

    @Volatile
    private var enabled = true

    @Volatile
    private var targetPackage: String? = null

    @Volatile
    private var processName: String = "main"

    private val accessCounts = ConcurrentHashMap<String, AtomicLong>()
    private val firstSeen = ConcurrentHashMap<String, Long>()
    private val lastSeen = ConcurrentHashMap<String, Long>()
    private val lastValues = ConcurrentHashMap<String, String>()
    private val spoofFlags = ConcurrentHashMap<String, Boolean>()
    private val logBuffer = Collections.synchronizedList(mutableListOf<String>())
    private val startTime = SystemClock.elapsedRealtime()
    private val dateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    private val spoofCount = AtomicLong(0)
    private val realCount = AtomicLong(0)
    val appliedHooks = AtomicInteger(0)

    private val CRITICAL_CATEGORIES = setOf(
        Category.IDENTITY, Category.NETWORK, Category.TELEPHONY,
        Category.ADVERTISING, Category.DRM
    )

    enum class Category(val label: String) {
        IDENTITY("IDENTITY"),
        NETWORK("NETWORK"),
        HARDWARE("HARDWARE"),
        TELEPHONY("TELEPHONY"),
        ADVERTISING("ADVERTISING"),
        DRM("DRM"),
        ENVIRONMENT("ENVIRONMENT"),
        ACCOUNT("ACCOUNT"),
        PACKAGE("PACKAGE"),
        FILESYSTEM("FILESYSTEM"),
        SETTINGS("SETTINGS"),
        RUNTIME("RUNTIME"),
    }

    fun init(packageName: String, process: String = "main") {
        targetPackage = packageName
        processName = process.replace(":", "_").replace("/", "_")
        accessCounts.clear()
        firstSeen.clear()
        lastSeen.clear()
        lastValues.clear()
        spoofFlags.clear()
        logBuffer.clear()
        spoofCount.set(0)
        realCount.set(0)
        appliedHooks.set(0)
    }

    fun setAppliedHookCount(count: Int) {
        appliedHooks.set(count)
    }

    fun incrementAppliedHooks() {
        appliedHooks.incrementAndGet()
    }

    /**
     * Record a data access event.
     *
     * @param category  Broad category (IDENTITY, NETWORK, etc.)
     * @param api       Specific API (e.g. "Settings.Secure.ANDROID_ID")
     * @param value     The value returned to the app (spoofed or real)
     * @param spoofed   Whether we intercepted and modified the value
     */
    fun record(
        category: Category,
        api: String,
        value: String?,
        spoofed: Boolean
    ) {
        if (!enabled) return

        val key = "${category.label}|$api"
        val now = System.currentTimeMillis()

        accessCounts.getOrPut(key) { AtomicLong(0) }.incrementAndGet()
        firstSeen.putIfAbsent(key, now)
        lastSeen[key] = now
        value?.let { lastValues[key] = it.take(64) }
        spoofFlags[key] = spoofed

        if (spoofed) spoofCount.incrementAndGet() else realCount.incrementAndGet()

        val ts = dateFormat.format(Date(now))
        val tid = Thread.currentThread().id
        val flag = if (spoofed) "SPOOF" else "REAL"
        val truncVal = value?.take(32) ?: "null"
        val line = "$ts [$flag] ${category.label} $api = $truncVal (tid=$tid)"

        synchronized(logBuffer) {
            logBuffer.add(line)
            if (logBuffer.size > MAX_LOG_LINES) {
                logBuffer.removeAt(0)
            }
        }
    }

    fun flush() {
        val pkg = targetPackage ?: return
        val dir = File("/data/data/$pkg/files")
        if (!dir.exists()) return

        val suffix = if (processName == "main") "" else "_$processName"

        try {
            File(dir, ".titan_access${suffix}.log").bufferedWriter().use { writer ->
                synchronized(logBuffer) {
                    logBuffer.forEach { writer.appendLine(it) }
                }
            }
        } catch (e: Throwable) {
            Log.e("TitanMonitor", "flush() log write FAILED: ${e.message}")
        }

        try {
            val criticalRealApis = mutableListOf<String>()
            spoofFlags.forEach { (key, isSpoofed) ->
                if (!isSpoofed) {
                    val parts = key.split("|", limit = 2)
                    val cat = parts[0]
                    if (CRITICAL_CATEGORIES.any { it.label == cat }) {
                        criticalRealApis.add(parts.getOrElse(1) { key })
                    }
                }
            }
            val hasCriticalReal = criticalRealApis.isNotEmpty()

            File(dir, ".titan_access_summary${suffix}.json").bufferedWriter().use { writer ->
                writer.appendLine("{")
                writer.appendLine("  \"package\": \"$pkg\",")
                writer.appendLine("  \"process_name\": \"$processName\",")
                writer.appendLine("  \"pid\": ${Process.myPid()},")
                writer.appendLine("  \"uid\": ${Process.myUid()},")
                writer.appendLine("  \"uptime_ms\": ${SystemClock.elapsedRealtime() - startTime},")
                writer.appendLine("  \"last_heartbeat_ms\": ${System.currentTimeMillis()},")
                writer.appendLine("  \"applied_hooks\": ${appliedHooks.get()},")
                writer.appendLine("  \"total_events\": ${accessCounts.values.sumOf { it.get() }},")
                writer.appendLine("  \"spoof_count\": ${spoofCount.get()},")
                writer.appendLine("  \"real_count\": ${realCount.get()},")
                writer.appendLine("  \"has_critical_real\": $hasCriticalReal,")

                val critJson = criticalRealApis.joinToString(", ") { "\"${it.replace("\"", "\\\"")}\"" }
                writer.appendLine("  \"real_critical_apis\": [$critJson],")

                writer.appendLine("  \"apis\": {")

                val entries = accessCounts.entries.sortedByDescending { it.value.get() }
                entries.forEachIndexed { i, (key, count) ->
                    val parts = key.split("|", limit = 2)
                    val cat = parts[0]
                    val api = parts.getOrElse(1) { key }
                    val first = firstSeen[key] ?: 0
                    val last = lastSeen[key] ?: 0
                    val lastVal = lastValues[key]?.replace("\"", "\\\"") ?: ""
                    val isSpoofed = spoofFlags[key] ?: false
                    val comma = if (i < entries.size - 1) "," else ""
                    writer.appendLine(
                        "    \"$api\": {\"category\": \"$cat\", \"count\": ${count.get()}, " +
                        "\"spoofed\": $isSpoofed, " +
                        "\"first_ms\": $first, \"last_ms\": $last, " +
                        "\"last_value\": \"$lastVal\"}$comma"
                    )
                }

                writer.appendLine("  }")
                writer.appendLine("}")
            }
        } catch (e: Throwable) {
            Log.e("TitanMonitor", "flush() JSON write FAILED: ${e.message}")
        }
}
}
