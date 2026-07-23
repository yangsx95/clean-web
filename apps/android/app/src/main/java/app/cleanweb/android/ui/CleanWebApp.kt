package app.cleanweb.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.cleanweb.android.vpn.VpnStatus

@Composable
fun CleanWebApp(
    status: VpnStatus,
    onStartProtection: () -> Unit,
    onStopProtection: () -> Unit
) {
    val protectionEnabled = status == VpnStatus.Running || status == VpnStatus.Starting

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            Text(
                text = "CleanWeb",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.SemiBold
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Protection",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = statusLabel(status),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(
                    checked = protectionEnabled,
                    onCheckedChange = { checked ->
                        if (checked) onStartProtection() else onStopProtection()
                    }
                )
            }

            Text(
                text = "VPN permission and service lifecycle are wired. Traffic capture remains disabled until the Mihomo data path is connected.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(8.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    enabled = !protectionEnabled,
                    onClick = onStartProtection
                ) {
                    Text("Start")
                }
                OutlinedButton(
                    enabled = protectionEnabled,
                    onClick = onStopProtection
                ) {
                    Text("Stop")
                }
            }
        }
    }
}

private fun statusLabel(status: VpnStatus): String {
    return when (status) {
        VpnStatus.Idle -> "Not running"
        VpnStatus.Starting -> "Starting VPN"
        VpnStatus.Running -> "VPN running"
        VpnStatus.PermissionDenied -> "VPN permission denied"
    }
}
