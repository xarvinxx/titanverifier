package com.titan.verifier

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import android.widget.Toast

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityAuditScreen() {
    val context = LocalContext.current
    var layeredSections by remember { mutableStateOf(emptyList<LayeredAuditSection>()) }
    var sections by remember { mutableStateOf(emptyList<AuditSection>()) }
    val expanded = remember { mutableStateMapOf<String, Boolean>() }
    var hasPhoneState by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED)
    }
    var auditTrigger by remember { mutableStateOf(0) }
    val scope = rememberCoroutineScope()
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasPhoneState = granted
        if (granted) auditTrigger++
    }

    fun runAudit() {
        // Identity sofort in Native synchronisieren, sobald verfügbar
        AuditEngine.syncIdentityToNative(context)
        
        // === Titan Hook Validation (Phase 4.2 Singularity) ===
        val validation = AuditEngine.getValidationSummary(context)
        val hookStatusSection = AuditSection(
            title = "0. Titan Singularity Status",
            rows = buildList {
                // Übersicht
                add(AuditRow(
                    label = "Hook Status",
                    value = validation.getStatusText(),
                    isCritical = !validation.allVerified,
                    forceRed = if (validation.configuredCount > 0) !validation.allVerified else null
                ))
                
                // Success Rate als Prozent
                val rateText = if (validation.configuredCount > 0) {
                    val percent = (validation.successRate * 100).toInt()
                    "$percent% (${validation.verifiedCount}/${validation.configuredCount})"
                } else {
                    "Bridge nicht geladen"
                }
                add(AuditRow(
                    label = "Success Rate",
                    value = rateText,
                    isCritical = validation.mismatchCount > 0,
                    forceRed = validation.mismatchCount > 0
                ))
                
                // Einzelne Felder mit verbesserter Darstellung
                val orderedKeys = listOf(
                    "serial", "boot_serial", "imei1", "imei2", 
                    "gsf_id", "android_id", "wifi_mac",
                    "imsi", "sim_serial", "widevine_id"
                )
                // Keys für die eine Hex/Dezimal-Alternativanzeige sinnvoll ist
                val altFormatKeys = setOf("gsf_id", "android_id", "imei1", "imei2", "imsi", "sim_serial")
                orderedKeys.forEach { key ->
                    val result = validation.results[key] ?: return@forEach
                    val rawValue = when (result.status) {
                        AuditEngine.HookStatus.VERIFIED -> "[T] ${result.expectedValue}"
                        AuditEngine.HookStatus.MISMATCH -> "⚠ ${result.displayValue.removePrefix("⚠ ")} (expected: ${result.expectedValue})"
                        AuditEngine.HookStatus.NOT_CONFIGURED -> "— (not in bridge)"
                        AuditEngine.HookStatus.EMPTY_CONFIG -> "— (empty)"
                    }
                    // Alt-Format nur bei Verified und passenden Keys
                    val displayValue = if (key in altFormatKeys && result.status == AuditEngine.HookStatus.VERIFIED && result.expectedValue != null) {
                        "[T] ${AuditEngine.withAltFormat(result.expectedValue!!)}"
                    } else rawValue
                    val isGreen = result.status == AuditEngine.HookStatus.VERIFIED
                    add(AuditRow(
                        label = key.replace("_", " ").replaceFirstChar { it.uppercase() },
                        value = displayValue,
                        isCritical = result.status == AuditEngine.HookStatus.MISMATCH,
                        forceRed = result.status == AuditEngine.HookStatus.MISMATCH
                    ))
                }
            }
        )

        // Layered Identity (Java | Native | Root)
        val layeredIdentity = LayeredAuditSection(
            title = "1. Layered Identity",
            rows = listOf(
                AuditEngine.getGsfIdLayered(context),
                AuditEngine.getAndroidIdLayered(context),
                AuditEngine.getImei1Layered(context),
                AuditEngine.getImei2Layered(context),
                AuditEngine.getSerialLayered(context),
                AuditEngine.getMacWlan0Layered()
            )
        )

        // Weitere Identity-Werte (nur Java, keine Layered)
        val imsi = AuditEngine.getImsi(context)
        val simSerial = AuditEngine.getSimSerial(context)
        val aaid = AuditEngine.getAdvertisingId(context)
        val nativeHookImei = AuditEngine.getNativeHookImei()
        val identitySection = AuditSection(
            title = "2. Identity (Weitere)",
            rows = listOf(
                AuditRow("IMSI (Subscriber ID)", AuditEngine.withAltFormat(imsi.ifEmpty { "—" }), isCritical = true),
                AuditRow("SIM Serial (ICCID)", AuditEngine.withAltFormat(simSerial.ifEmpty { "—" }), isCritical = false),
                AuditRow("Advertising ID (AAID)", aaid.ifEmpty { "—" }, isCritical = false),
                AuditRow("Native Hook-Memory", AuditEngine.withAltFormat(nativeHookImei.ifEmpty { "—" }), isCritical = false)
            )
        )

        // Hardware & Native (Build/ro)
        val bootSerial = AuditEngine.getBootSerial()
        val buildModel = Build.MODEL.ifEmpty { Build.UNKNOWN }
        val nativeModel = AuditEngine.getNativeProperty("MODEL")
        val buildBoard = Build.BOARD.ifEmpty { Build.UNKNOWN }
        val nativeBoard = AuditEngine.getNativeProperty("BOARD")
        val fingerprint = Build.FINGERPRINT.ifEmpty { Build.UNKNOWN }
        val hardwareSection = AuditSection(
            title = "3. Hardware & Native",
            rows = listOf(
                AuditRow("Boot Serial (ro.boot.serialno)", bootSerial.ifEmpty { "—" }, isCritical = false),
                AuditRow("Hardware Model (Build vs ro)", "$buildModel / $nativeModel", isCritical = false),
                AuditRow("Board Name (Build vs ro)", "$buildBoard / $nativeBoard", isCritical = false),
                AuditRow("Fingerprint", fingerprint, isCritical = false)
            )
        )

        // DRM & Security
        val widevineId = AuditEngine.getWidevineIdWithFallback(context)
        val securityPatch = Build.VERSION.SECURITY_PATCH.ifEmpty { "—" }
        val selinuxRaw = AuditEngine.getSelinuxEnforce()
        val selinuxStr = when (selinuxRaw) {
            1 -> "Enforcing (1)"
            0 -> "Permissive (0)"
            else -> "— (unreadable)"
        }
        val rootKsu = AuditEngine.checkRootForensics()
        val rootSu = AuditEngine.checkRootPath("/sbin/su")
        val rootStr = when {
            rootKsu && rootSu -> "KSU + /sbin/su found"
            rootKsu -> "KSU found"
            rootSu -> "/sbin/su found"
            else -> "None"
        }
        val privilegedContext = AuditEngine.isPrivilegedContext(context)
        val privilegedStr = if (privilegedContext) "Yes (FLAG_SYSTEM)" else "No"
        val detailedStatus = AuditEngine.getDetailedIdentityStatus(context)
        val privAppStr = if (detailedStatus.isUnderSystemPrivApp) "Yes" else "No"
        val permStatusStr = "Level=${detailedStatus.permissionProtectionLevel}, Granted=${detailedStatus.permissionGranted}"

        val drmSection = AuditSection(
            title = "4. DRM & Security",
            rows = listOf(
                AuditRow("Widevine ID", widevineId.ifEmpty { "—" }, isCritical = true),
                AuditRow("Security Patch", securityPatch, isCritical = false),
                AuditRow("SELinux Status", selinuxStr, isCritical = false),
                AuditRow("Root Check (statx)", rootStr, isCritical = true),
                AuditRow("Privileged Context (Connectivity Audit)", privilegedStr, isCritical = false),
                AuditRow("Under /system/priv-app", privAppStr, isCritical = false),
                AuditRow("READ_PRIVILEGED_PHONE_STATE", permStatusStr, isCritical = false),
                AuditRow("Package Path", detailedStatus.packageCodePath.ifEmpty { "—" }, isCritical = false)
            )
        )

        // Physical Hardware
        val gpuRenderer = AuditEngine.getGpuRenderer()
        val totalRam = AuditEngine.getTotalRam()
        val inputDeviceListNative = AuditEngine.getInputDeviceList()
        val inputDeviceListJava = AuditEngine.getInputDevicesJava(context)
        val inputCombined = when {
            inputDeviceListJava.isNotEmpty() && inputDeviceListJava != "No devices" && inputDeviceListJava != "InputManager unavailable" -> inputDeviceListJava
            inputDeviceListNative.isNotEmpty() -> inputDeviceListNative
            else -> "—"
        }
        val gpuRed = gpuRenderer.isNotEmpty() && !gpuRenderer.contains("Mali-G78")
        val ramGb = totalRam.replace(" GB", "").toDoubleOrNull() ?: 0.0
        val ramRed = ramGb < 7.0 || ramGb > 9.0
        val inputRed = inputCombined.contains("[EMULATOR]") ||
            inputCombined.contains("virtual", ignoreCase = true) ||
            inputCombined.contains("vbox", ignoreCase = true) ||
            inputCombined.contains("goldfish", ignoreCase = true)
        val inputOk = inputCombined != "—" && inputCombined != "No devices" && !inputRed
        
        // Display Audit
        val displayAudit = AuditEngine.getDisplayAudit(context)
        val displayStr = "${displayAudit.width}x${displayAudit.height} @ ${displayAudit.densityDpi}dpi"
        val displayRed = !displayAudit.isPixel6

        val physicalSection = AuditSection(
            title = "5. Physical Hardware",
            rows = listOf(
                AuditRow("GPU Renderer", gpuRenderer.ifEmpty { "—" }, isCritical = false, forceRed = if (gpuRenderer.isEmpty()) null else gpuRed),
                AuditRow("RAM (MemTotal)", totalRam.ifEmpty { "—" }, isCritical = false, forceRed = if (totalRam.isEmpty()) null else ramRed),
                AuditRow("Display Resolution", displayStr, isCritical = false, forceRed = displayRed),
                AuditRow("Input Devices (Java)", inputCombined.replace("\n", ", "), isCritical = false, forceRed = if (inputCombined == "—") null else inputRed),
                AuditRow("Input Devices (Native)", inputDeviceListNative.ifEmpty { "—" }.replace("\n", ", "), isCritical = false)
            )
        )

        // Network & Telemetry (erweitert mit Phase 10.0)
        val macWlan0 = AuditEngine.getMacAddressWlan0WithFallback()
        val operatorName = AuditEngine.getOperatorName(context)
        val bootloader = Build.BOOTLOADER.ifEmpty { Build.UNKNOWN }
        val telephony = AuditEngine.getTelephonyAudit(context)

        val networkSection = AuditSection(
            title = "6. Network & Telemetry",
            rows = listOf(
                AuditRow("MAC Address (WiFi wlan0)", macWlan0.ifEmpty { "—" }, isCritical = false),
                AuditRow("Operator Name", operatorName.ifEmpty { "—" }, isCritical = false),
                AuditRow("Phone Number", telephony.phoneNumber.ifEmpty { "—" }, isCritical = false),
                AuditRow("SIM Operator", "${telephony.simOperator} / ${telephony.simOperatorName}".ifEmpty { "—" }, isCritical = false),
                AuditRow("Network Operator", telephony.networkOperator.ifEmpty { "—" }, isCritical = false),
                AuditRow("SIM Country", telephony.simCountryIso.ifEmpty { "—" }, isCritical = false),
                AuditRow("Phone Type", telephony.phoneType.ifEmpty { "—" }, isCritical = false),
                AuditRow("Network Type", telephony.networkType.ifEmpty { "—" }, isCritical = false),
                AuditRow("Bootloader", bootloader, isCritical = false)
            )
        )

        // === 7. Forensics & Stealth (Phase 10.0 / 13.5) ===
        val battery = AuditEngine.getBatteryStatus(context)
        val buildProps = AuditEngine.getBuildPropertyAudit()
        val sensor = AuditEngine.getSensorAudit(context)
        val stealth = AuditEngine.getStealthAudit(context)
        val identityProfile = AuditEngine.getIdentityProfile()
        
        val batteryStr = "${battery.level}% / ${battery.temperature}°C / ${battery.voltage}mV"
        val batteryRed = !battery.isRealistic
        
        val sensorStr = "${sensor.totalCount} Sensors"
        val sensorRed = sensor.hasVirtual || sensor.hasMock
        val sensorDetail = if (sensor.sensorNames.size <= 5) {
            sensor.sensorNames.joinToString(", ")
        } else {
            sensor.sensorNames.take(5).joinToString(", ") + " +${sensor.sensorNames.size - 5} more"
        }
        
        val stealthStr = if (stealth.suspiciousPackages.isEmpty()) "Clean" 
            else "Detected: ${stealth.suspiciousPackages.joinToString(", ")}"
        val stealthRed = stealth.suspiciousPackages.isNotEmpty()

        val forensicsSection = AuditSection(
            title = "7. Forensics & Stealth",
            rows = buildList {
                add(AuditRow("Identity Profile", identityProfile, isCritical = false))
                add(AuditRow("Battery Status", batteryStr, isCritical = false, forceRed = batteryRed))
                add(AuditRow("Battery Health", battery.health, isCritical = false))
                add(AuditRow("Charging", if (battery.isCharging) "Yes" else "No", isCritical = false))
                add(AuditRow("Battery Realistic", if (battery.isRealistic) "Yes (Anti-Emu OK)" else "No (Suspicious!)", isCritical = false, forceRed = batteryRed))
                add(AuditRow("Build Props", if (buildProps.isConsistent) "All OK (${buildProps.properties.size})" else "${buildProps.mismatchCount} Mismatches", isCritical = false, forceRed = !buildProps.isConsistent))
                // Stichprobe der Properties
                for ((key, value) in buildProps.properties) {
                    add(AuditRow("  $key", value, isCritical = false, forceRed = value.startsWith("⚠")))
                }
                add(AuditRow("Display Match (Pixel 6)", if (displayAudit.isPixel6) "OK (1080x2400@411)" else "Mismatch ($displayStr)", isCritical = false, forceRed = displayRed))
                add(AuditRow("Sensor Count", sensorStr, isCritical = false))
                add(AuditRow("Sensor List", sensorDetail, isCritical = false))
                add(AuditRow("Virtual Sensors", if (sensor.hasVirtual) "Detected!" else "None", isCritical = false, forceRed = sensorRed))
                add(AuditRow("Mock Sensors", if (sensor.hasMock) "Detected!" else "None", isCritical = false, forceRed = sensorRed))
                add(AuditRow("Package Stealth", stealthStr, isCritical = false, forceRed = stealthRed))
                add(AuditRow("Self Visible", if (stealth.selfVisible) "Yes" else "Hidden", isCritical = false))
            }
        )

        // === 8. Java ↔ Native Consistency Check (Phase 15.0) ===
        val consistency = AuditEngine.checkConsistency(context)
        val consistencySection = AuditSection(
            title = "8. Java ↔ Native Consistency",
            rows = buildList {
                val totalStr = "${consistency.consistentCount}/${consistency.totalChecks} consistent"
                val hasIssue = consistency.inconsistentCount > 0
                add(AuditRow("Consistency Score", totalStr, isCritical = hasIssue, forceRed = hasIssue))
                if (hasIssue) {
                    add(AuditRow("⚠ Inconsistencies", "${consistency.inconsistentCount} detected", isCritical = true, forceRed = true))
                }
                for (item in consistency.items) {
                    val statusIcon = if (item.isConsistent) "✓" else "✗"
                    val detail = if (item.javaValue == item.nativeValue || item.nativeValue.isEmpty()) {
                        "$statusIcon ${item.javaValue.take(50)}"
                    } else {
                        "$statusIcon Java=${item.javaValue.take(25)} | Native=${item.nativeValue.take(25)}"
                    }
                    add(AuditRow("  ${item.label}", detail, isCritical = !item.isConsistent, forceRed = !item.isConsistent))
                }
            }
        )

        layeredSections = listOf(layeredIdentity)
        sections = listOf(hookStatusSection, identitySection, hardwareSection, drmSection, physicalSection, networkSection, forensicsSection, consistencySection)
        layeredSections.forEach { expanded[it.title] = expanded[it.title] ?: true }
        // Hook Status immer expanded, Rest collapsed
        sections.forEachIndexed { idx, sec -> 
            expanded[sec.title] = expanded[sec.title] ?: (idx == 0) 
        }
    }

    LaunchedEffect(Unit, auditTrigger) { withContext(Dispatchers.Default) { runAudit() } }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "Ground Truth Auditor",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                actions = {
                    FilledTonalButton(
                        onClick = {
                            val result = AuditExporter.buildReport(layeredSections, sections)
                            val copied = AuditExporter.exportToClipboard(context, result.report)
                            val file = AuditExporter.exportToFile(context, result.report)
                            val msg = buildString {
                                if (copied) append("Export in Zwischenablage. ")
                                file?.let { append("Download/${it.name} ") }
                                append("${result.missingCount} fehlen")
                            }
                            Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                        },
                        modifier = Modifier.padding(end = 8.dp),
                        contentPadding = ButtonDefaults.ContentPadding
                    ) {
                        Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Export", fontSize = 13.sp)
                    }
                    FilledTonalButton(
                        onClick = {
                            val ok = RootShell.forceGrantPrivilegedPermission()
                            Toast.makeText(context, if (ok) "Grant versucht" else "Grant fehlgeschlagen", Toast.LENGTH_SHORT).show()
                            if (ok) scope.launch(Dispatchers.Default) { runAudit() }
                        },
                        modifier = Modifier.padding(end = 8.dp),
                        contentPadding = ButtonDefaults.ContentPadding
                    ) {
                        Text("Grant Priv", fontSize = 12.sp)
                    }
                    FilledTonalButton(
                        onClick = { scope.launch(Dispatchers.Default) { runAudit() } },
                        modifier = Modifier.padding(end = 12.dp),
                        contentPadding = ButtonDefaults.ContentPadding
                    ) {
                        Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Refresh", fontSize = 13.sp)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 12.dp)
        ) {
            if (!hasPhoneState) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "READ_PHONE_STATE fehlt (IMEI/IMSI)",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Button(onClick = { permissionLauncher.launch(Manifest.permission.READ_PHONE_STATE) }) {
                            Text("Grant")
                        }
                    }
                }
            }
            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(rememberScrollState())
                    .padding(bottom = 20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                layeredSections.forEach { section ->
                    ExpandableLayeredSection(
                        section = section,
                        isExpanded = expanded[section.title] == true,
                        onToggle = { expanded[section.title] = !(expanded[section.title] ?: true) }
                    )
                }
                sections.forEach { section ->
                    ExpandableSection(
                        section = section,
                        isExpanded = expanded[section.title] == true,
                        onToggle = { expanded[section.title] = !(expanded[section.title] ?: true) }
                    )
                }
            }
        }
    }
}

@Composable
private fun ExpandableLayeredSection(
    section: LayeredAuditSection,
    isExpanded: Boolean,
    onToggle: () -> Unit
) {
    SectionCard(
        title = section.title,
        isExpanded = isExpanded,
        onToggle = onToggle
    ) {
        section.rows.forEachIndexed { idx, row ->
            if (idx > 0) Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(1.dp)
                    .background(MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
            )
            LayeredAuditRowItem(row = row)
        }
    }
}

@Composable
private fun LayeredAuditRowItem(row: LayeredAuditRow) {
    val (statusColor, statusBg) = when (row.status) {
        LayeredStatus.INCONSISTENT -> Color(0xFFC62828) to Color(0xFFC62828).copy(alpha = 0.12f)
        LayeredStatus.SPOOFED -> Color(0xFF2E7D32) to Color(0xFF2E7D32).copy(alpha = 0.12f)
        LayeredStatus.CONSISTENT -> Color(0xFF2E7D32) to Color(0xFF2E7D32).copy(alpha = 0.12f)
        LayeredStatus.MISSING -> Color(0xFFEF6C00) to Color(0xFFEF6C00).copy(alpha = 0.12f)
        LayeredStatus.N_A -> MaterialTheme.colorScheme.onSurfaceVariant to MaterialTheme.colorScheme.surfaceVariant
    }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = row.label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(statusBg)
                    .padding(horizontal = 8.dp, vertical = 3.dp)
            ) {
                Text(
                    text = row.status.name,
                    style = MaterialTheme.typography.labelMedium,
                    color = statusColor,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 6.dp),
            verticalArrangement = Arrangement.spacedBy(3.dp)
        ) {
            LayerChip("Java", row.javaValue)
            LayerChip("Native", row.nativeValue)
            LayerChip("Root", row.rootValue)
        }
    }
}

@Composable
private fun LayerChip(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(48.dp)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            maxLines = 3,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun SectionCard(
    title: String,
    isExpanded: Boolean,
    onToggle: () -> Unit,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 52.dp)
                    .clickable(onClick = onToggle)
                    .padding(horizontal = 14.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Icon(
                    imageVector = if (isExpanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                    contentDescription = if (isExpanded) "Einklappen" else "Aufklappen"
                )
            }
            AnimatedVisibility(
                visible = isExpanded,
                enter = expandVertically(),
                exit = shrinkVertically()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp)
                        .padding(bottom = 14.dp)
                ) {
                    content()
                }
            }
        }
    }
}

@Composable
private fun ExpandableSection(
    section: AuditSection,
    isExpanded: Boolean,
    onToggle: () -> Unit
) {
    SectionCard(
        title = section.title,
        isExpanded = isExpanded,
        onToggle = onToggle
    ) {
        section.rows.forEachIndexed { idx, row ->
            if (idx > 0) Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(1.dp)
                    .background(MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
            )
            AuditRowItem(row = row)
        }
    }
}

@Composable
private fun AuditRowItem(row: AuditRow) {
    val isEmpty = row.value.isBlank() || row.value == "—"
    val isRed = row.forceRed == true || (row.isCritical && isEmpty)
    val textColor = if (isRed) Color(0xFFC62828) else MaterialTheme.colorScheme.onSurface
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
    ) {
        Text(
            text = row.label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = row.value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
            color = textColor,
            maxLines = 3,
            overflow = TextOverflow.Ellipsis
        )
    }
}
