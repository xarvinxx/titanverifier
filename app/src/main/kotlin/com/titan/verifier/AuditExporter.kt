package com.titan.verifier

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Exportiert Audit-Daten und markiert fehlende Werte (MISSING).
 */
object AuditExporter {

    private fun isMissing(s: String): Boolean = s.isBlank() || s == "—"

    data class ExportResult(val report: String, val missingCount: Int)

    fun buildReport(
        layeredSections: List<LayeredAuditSection>,
        sections: List<AuditSection>
    ): ExportResult {
        val sb = StringBuilder()
        val missing = mutableListOf<String>()
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

        // Identity Profile Header
        val identityProfile = try { 
            com.titan.verifier.AuditEngine.getIdentityProfile() 
        } catch (_: Throwable) { "Unknown" }

        sb.appendLine("=== Ground Truth Auditor – Export ===")
        sb.appendLine("Datum: ${fmt.format(Date())}")
        sb.appendLine("Gerät: ${Build.MODEL}, Android ${Build.VERSION.SDK_INT}")
        sb.appendLine("Identity Profile: $identityProfile")
        sb.appendLine()

        for (sec in layeredSections) {
            sb.appendLine("--- ${sec.title} ---")
            for (row in sec.rows) {
                val jOk = !isMissing(row.javaValue)
                val nOk = !isMissing(row.nativeValue)
                val rOk = !isMissing(row.rootValue)
                val isMissingRow = !jOk && !nOk && !rOk || row.status == LayeredStatus.MISSING
                if (isMissingRow) missing.add(row.label)
                val status = if (isMissingRow) "[MISSING]" else "[${row.status}]"
                sb.appendLine("  ${row.label}:")
                sb.appendLine("    Java=${row.javaValue} Native=${row.nativeValue} Root=${row.rootValue}")
                sb.appendLine("    $status")
            }
            sb.appendLine()
        }

        for (sec in sections) {
            sb.appendLine("--- ${sec.title} ---")
            for (row in sec.rows) {
                val ok = !isMissing(row.value)
                // Sub-property rows (indented labels) don't count as missing
                val isSubRow = row.label.startsWith("  ")
                if (!ok && !isSubRow) missing.add(row.label)
                sb.appendLine("  ${row.label}: ${row.value} ${if (ok) "[OK]" else "[MISSING]"}")
            }
            sb.appendLine()
        }

        sb.appendLine("=== FEHLENDE WERTE (${missing.size}) ===")
        if (missing.isEmpty()) {
            sb.appendLine("Keine – alle Werte vorhanden.")
        } else {
            missing.forEach { sb.appendLine("  - $it") }
        }
        return ExportResult(sb.toString(), missing.size)
    }

    fun exportToClipboard(context: Context, report: String): Boolean {
        return try {
            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return false
            cm.setPrimaryClip(ClipData.newPlainText("Ground Truth Audit", report))
            true
        } catch (_: Throwable) { false }
    }

    fun exportToFile(context: Context, report: String): File? {
        val name = "audit_export_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.txt"
        val cacheFile = File(context.cacheDir, "audit_export_latest.txt")
        try { cacheFile.writeText(report) } catch (_: Throwable) { }
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                val values = android.content.ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                }
                val uri = context.contentResolver.insert(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    values
                )
                uri?.let {
                    context.contentResolver.openOutputStream(it)?.use { out: OutputStream ->
                        out.write(report.toByteArray())
                    }
                    return File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), name)
                }
            }
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val file = File(dir, name)
            file.writeText(report)
            return file
        } catch (_: Throwable) { }
        return try {
            val dir = context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS)
                ?: context.getExternalFilesDir(null) ?: context.filesDir
            File(dir, name).apply { writeText(report) }
        } catch (_: Throwable) { null }
    }
}
