package com.titan.verifier

import android.os.Build
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityAuditScreen() {
    var cards by remember { mutableStateOf(emptyList<SecurityCard>()) }

    fun runAudit() {
        val javaSerial = Build.SERIAL.ifEmpty { Build.UNKNOWN }
        val javaModel = Build.MODEL.ifEmpty { Build.UNKNOWN }
        val javaId = Build.ID.ifEmpty { Build.UNKNOWN }
        val javaFingerprint = Build.FINGERPRINT.ifEmpty { Build.UNKNOWN }

        val nativeSerial = AuditEngine.getNativeProperty("SERIAL")
        val nativeModel = AuditEngine.getNativeProperty("MODEL")
        val nativeId = AuditEngine.getNativeProperty("ID")
        val nativeFingerprint = AuditEngine.getNativeProperty("FINGERPRINT")

        val serialOk = javaSerial == nativeSerial
        cards = listOf(
            SecurityCard(
                name = "Serial Number",
                javaValue = javaSerial,
                nativeValue = nativeSerial,
                status = if (serialOk) CardStatus.OK else CardStatus.ALERT
            ),
            SecurityCard(
                name = "Model",
                javaValue = javaModel,
                nativeValue = nativeModel,
                status = CardStatus.OK
            ),
            SecurityCard(
                name = "Build ID",
                javaValue = javaId,
                nativeValue = nativeId,
                status = CardStatus.OK
            ),
            SecurityCard(
                name = "Fingerprint",
                javaValue = javaFingerprint,
                nativeValue = nativeFingerprint,
                status = CardStatus.OK
            )
        )
    }

    LaunchedEffect(Unit) { runAudit() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Titan Security Audit", fontWeight = FontWeight.Bold) },
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
                .padding(16.dp)
        ) {
            Button(
                onClick = { runAudit() },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Refresh Audit")
            }
            Spacer(modifier = Modifier.height(16.dp))
            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (cards.isEmpty()) {
                    Text(
                        "Tippe auf „Refresh Audit“, um Build- und Native-Werte zu laden.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    cards.forEach { card ->
                        SecurityCardItem(card = card)
                    }
                }
            }
        }
    }
}

@Composable
private fun SecurityCardItem(card: SecurityCard) {
    val statusColor = when (card.status) {
        CardStatus.OK -> Color(0xFF2E7D32)
        CardStatus.ALERT -> Color(0xFFC62828)
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = card.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Box(
                    modifier = Modifier
                        .background(statusColor, RoundedCornerShape(8.dp))
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = if (card.status == CardStatus.OK) "OK" else "ALERT",
                        color = Color.White,
                        style = MaterialTheme.typography.labelMedium
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Java: ${card.javaValue.ifEmpty { "—" }}",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            if (card.nativeValue != null) {
                Text(
                    text = "Native: ${card.nativeValue.ifEmpty { "—" }}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }
        }
    }
}
