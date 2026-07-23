package app.cleanweb.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import app.cleanweb.android.model.AccessLogEntry
import app.cleanweb.android.model.CleanWebState
import app.cleanweb.android.model.LogDecision
import app.cleanweb.android.model.ProtectionSettings
import app.cleanweb.android.model.ProxySubscription
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import app.cleanweb.android.model.RuleEntry
import app.cleanweb.android.vpn.VpnStatus

@Composable
fun CleanWebApp(
    appState: CleanWebState,
    status: VpnStatus,
    onStartProtection: () -> Unit,
    onStopProtection: () -> Unit,
    onSettingsChange: (ProtectionSettings) -> Unit,
    onAddRule: (String, RuleCategory, RuleAction) -> Unit,
    onToggleRule: (String) -> Unit,
    onRemoveRule: (String) -> Unit,
    onAddProxySubscription: (String, String) -> Unit,
    onToggleProxySubscription: (String) -> Unit,
    onRemoveProxySubscription: (String) -> Unit,
    onClearLogs: () -> Unit,
    onAcknowledgeAlwaysOnGuidance: () -> Unit
) {
    var selectedTab by remember { mutableStateOf(AppTab.Protection) }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Scaffold(
            bottomBar = {
                NavigationBar {
                    AppTab.entries.forEach { tab ->
                        NavigationBarItem(
                            selected = selectedTab == tab,
                            onClick = { selectedTab = tab },
                            icon = { Text(tab.icon) },
                            label = { Text(tab.label) }
                        )
                    }
                }
            }
        ) { padding ->
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 20.dp, vertical = 18.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                item {
                    Header(status)
                }

                when (selectedTab) {
                    AppTab.Protection -> {
                        item {
                            ProtectionPanel(
                                state = appState,
                                status = status,
                                onStartProtection = onStartProtection,
                                onStopProtection = onStopProtection,
                                onSettingsChange = onSettingsChange,
                                onAcknowledgeAlwaysOnGuidance = onAcknowledgeAlwaysOnGuidance
                            )
                        }
                    }

                    AppTab.Rules -> {
                        item {
                            RulesEditor(onAddRule)
                        }
                        items(appState.rules, key = { it.id }) { rule ->
                            RuleRow(
                                rule = rule,
                                onToggleRule = onToggleRule,
                                onRemoveRule = onRemoveRule
                            )
                        }
                    }

                    AppTab.Proxy -> {
                        item {
                            ProxyEditor(onAddProxySubscription)
                        }
                        items(appState.proxySubscriptions, key = { it.id }) { subscription ->
                            ProxyRow(
                                subscription = subscription,
                                onToggleProxySubscription = onToggleProxySubscription,
                                onRemoveProxySubscription = onRemoveProxySubscription
                            )
                        }
                        if (appState.proxySubscriptions.isEmpty()) {
                            item {
                                EmptyState("No proxy subscriptions imported.")
                            }
                        }
                    }

                    AppTab.Logs -> {
                        item {
                            LogsHeader(
                                enabled = appState.settings.accessLogsEnabled,
                                onClearLogs = onClearLogs
                            )
                        }
                        items(appState.logs, key = { it.id }) { log ->
                            LogRow(log)
                        }
                        if (appState.logs.isEmpty()) {
                            item {
                                EmptyState("No local access events yet.")
                            }
                        }
                    }

                    AppTab.Settings -> {
                        item {
                            SettingsPanel(
                                settings = appState.settings,
                                onSettingsChange = onSettingsChange
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Header(status: VpnStatus) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = "CleanWeb",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.SemiBold
        )
        Text(
            text = statusLabel(status),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ProtectionPanel(
    state: CleanWebState,
    status: VpnStatus,
    onStartProtection: () -> Unit,
    onStopProtection: () -> Unit,
    onSettingsChange: (ProtectionSettings) -> Unit,
    onAcknowledgeAlwaysOnGuidance: () -> Unit
) {
    val protectionEnabled = status == VpnStatus.Running || status == VpnStatus.Starting

    SectionCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Total protection", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = if (protectionEnabled) "Android VPN service is active." else "VPN service is stopped.",
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

        Spacer(modifier = Modifier.height(16.dp))

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

    SectionCard {
        Text("Policy summary", style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(10.dp))
        SummaryRow("Enabled rules", state.rules.count { it.enabled }.toString())
        SummaryRow("Proxy sources", state.proxySubscriptions.count { it.enabled }.toString())
        SummaryRow("Access logs", state.logs.size.toString())
        SummaryRow("Filtering engine", "Mihomo + tun2socks")
    }

    if (!state.settings.alwaysOnVpnGuidanceSeen) {
        SectionCard {
            Text("Always-on VPN", style = MaterialTheme.typography.titleMedium)
            Text(
                text = "Use Android system VPN settings to enable always-on VPN and block connections without VPN after full-tunnel filtering is validated.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            TextButton(onClick = onAcknowledgeAlwaysOnGuidance) {
                Text("Got it")
            }
        }
    }

    ToggleRow(
        title = "Safe search",
        subtitle = "Prepare DNS safe-search mapping state for the Android data path.",
        checked = state.settings.safeSearchEnabled,
        onCheckedChange = {
            onSettingsChange(state.settings.copy(safeSearchEnabled = it))
        }
    )
}

@Composable
private fun RulesEditor(onAddRule: (String, RuleCategory, RuleAction) -> Unit) {
    var pattern by remember { mutableStateOf("") }
    var allowRule by remember { mutableStateOf(false) }

    SectionCard {
        Text("Add rule", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = pattern,
            onValueChange = { pattern = it.trim() },
            label = { Text("Domain or CIDR") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None)
        )
        ToggleRow(
            title = "Allow rule",
            subtitle = "Use for explicit parent allowlist entries.",
            checked = allowRule,
            onCheckedChange = { allowRule = it }
        )
        Button(
            enabled = pattern.isNotBlank(),
            onClick = {
                onAddRule(
                    pattern,
                    if (allowRule) RuleCategory.CustomAllow else RuleCategory.CustomBlock,
                    if (allowRule) RuleAction.Allow else RuleAction.Block
                )
                pattern = ""
                allowRule = false
            }
        ) {
            Text("Add")
        }
    }
}

@Composable
private fun RuleRow(
    rule: RuleEntry,
    onToggleRule: (String) -> Unit,
    onRemoveRule: (String) -> Unit
) {
    SectionCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(rule.pattern, style = MaterialTheme.typography.titleMedium)
                Text(
                    "${rule.category.label} / ${rule.action.label}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = rule.enabled,
                onCheckedChange = { onToggleRule(rule.id) }
            )
        }
        if (!rule.id.startsWith("core-")) {
            TextButton(onClick = { onRemoveRule(rule.id) }) {
                Text("Remove")
            }
        }
    }
}

@Composable
private fun ProxyEditor(onAddProxySubscription: (String, String) -> Unit) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }

    SectionCard {
        Text("Import proxy subscription", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = name,
            onValueChange = { name = it },
            label = { Text("Name") },
            singleLine = true
        )
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = url,
            onValueChange = { url = it.trim() },
            label = { Text("Subscription URL") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None)
        )
        Button(
            enabled = name.isNotBlank() && url.startsWith("https://"),
            onClick = {
                onAddProxySubscription(name.trim(), url)
                name = ""
                url = ""
            }
        ) {
            Text("Import")
        }
        Text(
            text = "Proxy subscriptions are routed by the local Android Mihomo data path.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ProxyRow(
    subscription: ProxySubscription,
    onToggleProxySubscription: (String) -> Unit,
    onRemoveProxySubscription: (String) -> Unit
) {
    SectionCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(subscription.name, style = MaterialTheme.typography.titleMedium)
                Text(
                    subscription.url,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = subscription.enabled,
                onCheckedChange = { onToggleProxySubscription(subscription.id) }
            )
        }
        TextButton(onClick = { onRemoveProxySubscription(subscription.id) }) {
            Text("Remove")
        }
    }
}

@Composable
private fun LogsHeader(enabled: Boolean, onClearLogs: () -> Unit) {
    SectionCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Access logs", style = MaterialTheme.typography.titleMedium)
                Text(
                    if (enabled) "Local logging is enabled." else "Local logging is disabled.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            OutlinedButton(onClick = onClearLogs) {
                Text("Clear")
            }
        }
    }
}

@Composable
private fun LogRow(log: AccessLogEntry) {
    SectionCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(log.target, style = MaterialTheme.typography.titleMedium)
            Text(log.timeLabel, style = MaterialTheme.typography.bodySmall)
        }
        Text(
            "${log.decision.label}: ${log.reason}",
            style = MaterialTheme.typography.bodyMedium,
            color = when (log.decision) {
                LogDecision.Blocked -> MaterialTheme.colorScheme.error
                LogDecision.Warning -> MaterialTheme.colorScheme.secondary
                LogDecision.Allowed -> MaterialTheme.colorScheme.onSurfaceVariant
            }
        )
    }
}

@Composable
private fun SettingsPanel(
    settings: ProtectionSettings,
    onSettingsChange: (ProtectionSettings) -> Unit
) {
    ToggleRow(
        title = "Proxy routing",
        subtitle = "Allowed traffic uses imported proxy nodes when the Android engine is connected.",
        checked = settings.proxyEnabled,
        onCheckedChange = { onSettingsChange(settings.copy(proxyEnabled = it)) }
    )
    ToggleRow(
        title = "Strict mode",
        subtitle = "Prepare stricter high-risk domain and CIDR policy state.",
        checked = settings.strictModeEnabled,
        onCheckedChange = { onSettingsChange(settings.copy(strictModeEnabled = it)) }
    )
    ToggleRow(
        title = "Ads and tracking",
        subtitle = "Optional ad and tracker category.",
        checked = settings.adsTrackingEnabled,
        onCheckedChange = { onSettingsChange(settings.copy(adsTrackingEnabled = it)) }
    )
    ToggleRow(
        title = "Access logs",
        subtitle = "Store local access decisions on this device.",
        checked = settings.accessLogsEnabled,
        onCheckedChange = { onSettingsChange(settings.copy(accessLogsEnabled = it)) }
    )
    ToggleRow(
        title = "Auto select node",
        subtitle = "Prefer healthy proxy nodes after latency testing is available.",
        checked = settings.autoSelectNode,
        onCheckedChange = { onSettingsChange(settings.copy(autoSelectNode = it)) }
    )
}

@Composable
private fun ToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    SectionCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(checked = checked, onCheckedChange = onCheckedChange)
        }
    }
}

@Composable
private fun SummaryRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
    }
    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
}

@Composable
private fun EmptyState(message: String) {
    SectionCard {
        Text(
            message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun SectionCard(content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            content = content
        )
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

private enum class AppTab(val label: String, val icon: String) {
    Protection("Protect", "P"),
    Rules("Rules", "R"),
    Proxy("Proxy", "X"),
    Logs("Logs", "L"),
    Settings("Settings", "S")
}
