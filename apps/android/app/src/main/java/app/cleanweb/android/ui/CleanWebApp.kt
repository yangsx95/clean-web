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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.cleanweb.android.model.AccessLogEntry
import app.cleanweb.android.model.CleanWebState
import app.cleanweb.android.model.LogDecision
import app.cleanweb.android.model.ProtectionSettings
import app.cleanweb.android.model.ProxySubscription
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import app.cleanweb.android.model.RuleEntry
import app.cleanweb.android.model.RuleMatchKind
import app.cleanweb.android.vpn.VpnStatus

@Composable
fun CleanWebApp(
    appState: CleanWebState,
    status: VpnStatus,
    vpnError: String?,
    onStartProtection: () -> Unit,
    onStopProtection: () -> Unit,
    onSettingsChange: (ProtectionSettings) -> Unit,
    onAddRule: (String, RuleCategory, RuleAction, RuleMatchKind) -> Unit,
    onToggleRule: (String) -> Unit,
    onRemoveRule: (String) -> Unit,
    onAddProxySubscription: (String, String) -> Unit,
    onImportProxyConfigFile: () -> Unit,
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
                                vpnError = vpnError,
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
                            ProxyEditor(
                                onAddProxySubscription = onAddProxySubscription,
                                onImportProxyConfigFile = onImportProxyConfigFile
                            )
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
                                EmptyState("还没有导入代理订阅。")
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
                                EmptyState("还没有本地访问事件。")
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
    vpnError: String?,
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
                Text("总保护", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = when (status) {
                        VpnStatus.Starting -> "安卓 VPN 正在启动。"
                        VpnStatus.Running -> "安卓 VPN 服务正在运行。"
                        VpnStatus.Failed -> vpnError ?: "启动失败，请查看日志中的失败原因。"
                        VpnStatus.PermissionDenied -> "未获得安卓 VPN 权限。"
                        VpnStatus.Idle -> "VPN 服务已停止。"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = if (status == VpnStatus.Failed) 5 else Int.MAX_VALUE,
                    overflow = TextOverflow.Ellipsis
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
                Text("开启")
            }
            OutlinedButton(
                enabled = protectionEnabled,
                onClick = onStopProtection
            ) {
                Text("关闭")
            }
        }
    }

    SectionCard {
        Text("策略概览", style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(10.dp))
        SummaryRow("已启用规则", state.rules.count { it.enabled }.toString())
        SummaryRow("代理来源", state.proxySubscriptions.count { it.enabled }.toString())
        SummaryRow("访问日志", state.logs.size.toString())
        SummaryRow("过滤内核", "Mihomo + tun2socks")
    }

    if (!state.settings.alwaysOnVpnGuidanceSeen) {
        SectionCard {
            Text("始终开启 VPN", style = MaterialTheme.typography.titleMedium)
            Text(
                text = "真机验证全流量过滤稳定后，可在安卓系统 VPN 设置里开启始终开启 VPN 和无 VPN 时阻止连接。",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            TextButton(onClick = onAcknowledgeAlwaysOnGuidance) {
                Text("知道了")
            }
        }
    }

    ToggleRow(
        title = "安全搜索",
        subtitle = "为安卓数据通道准备 DNS 安全搜索映射。",
        checked = state.settings.safeSearchEnabled,
        onCheckedChange = {
            onSettingsChange(state.settings.copy(safeSearchEnabled = it))
        }
    )
}

@Composable
private fun RulesEditor(onAddRule: (String, RuleCategory, RuleAction, RuleMatchKind) -> Unit) {
    var pattern by remember { mutableStateOf("") }
    var action by remember { mutableStateOf(RuleAction.Block) }
    var matchKind by remember { mutableStateOf(RuleMatchKind.Suffix) }

    SectionCard {
        Text("添加规则", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = pattern,
            onValueChange = { pattern = it.trim() },
            label = { Text("域名或 CIDR") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None)
        )
        Text("动作", style = MaterialTheme.typography.labelLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            RuleAction.entries.forEach { item ->
                OutlinedButton(onClick = { action = item }) {
                    Text(if (action == item) "✓ ${item.label}" else item.label)
                }
            }
        }
        Text("匹配方式", style = MaterialTheme.typography.labelLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            RuleMatchKind.entries.forEach { item ->
                OutlinedButton(onClick = { matchKind = item }) {
                    Text(if (matchKind == item) "✓ ${item.label}" else item.label)
                }
            }
        }
        Button(
            enabled = pattern.isNotBlank(),
            onClick = {
                onAddRule(
                    pattern,
                    when (action) {
                        RuleAction.Block -> RuleCategory.CustomBlock
                        RuleAction.Allow -> RuleCategory.CustomAllow
                        RuleAction.Proxy -> RuleCategory.Routing
                    },
                    action,
                    matchKind
                )
                pattern = ""
                action = RuleAction.Block
                matchKind = RuleMatchKind.Suffix
            }
        ) {
            Text("添加")
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
                Text(
                    rule.matchKind.label,
                    style = MaterialTheme.typography.bodySmall,
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
                Text("删除")
            }
        }
    }
}

@Composable
private fun ProxyEditor(
    onAddProxySubscription: (String, String) -> Unit,
    onImportProxyConfigFile: () -> Unit
) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }

    SectionCard {
        Text("导入代理订阅", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = name,
            onValueChange = { name = it },
            label = { Text("名称") },
            singleLine = true
        )
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = url,
            onValueChange = { url = it.trim() },
            label = { Text("订阅链接") },
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
            Text("导入订阅")
        }
        OutlinedButton(onClick = onImportProxyConfigFile) {
            Text("导入配置文件")
        }
        Text(
            text = "代理订阅和本地配置文件都会由安卓 Mihomo 数据通道处理；配置文件只保留可用代理节点。",
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
                    if (subscription.localProviderFileName == null) subscription.url else "本地配置文件 · ${subscription.importedNodeCount} 个节点",
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
            Text("删除")
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
                Text("访问日志", style = MaterialTheme.typography.titleMedium)
                Text(
                    if (enabled) "本地日志已开启。" else "本地日志已关闭。",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            OutlinedButton(onClick = onClearLogs) {
                Text("清空")
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
        title = "代理路由",
        subtitle = "安卓内核连接后，允许的流量会使用导入的代理节点。",
        checked = settings.proxyEnabled,
        onCheckedChange = { onSettingsChange(settings.copy(proxyEnabled = it)) }
    )
    ToggleRow(
        title = "严格模式",
        subtitle = "准备更严格的高风险域名和 CIDR 策略。",
        checked = settings.strictModeEnabled,
        onCheckedChange = { onSettingsChange(settings.copy(strictModeEnabled = it)) }
    )
    ToggleRow(
        title = "广告与跟踪",
        subtitle = "可选的广告和跟踪器类别。",
        checked = settings.adsTrackingEnabled,
        onCheckedChange = { onSettingsChange(settings.copy(adsTrackingEnabled = it)) }
    )
    ToggleRow(
        title = "访问日志",
        subtitle = "在本机保存访问决策记录。",
        checked = settings.accessLogsEnabled,
        onCheckedChange = { onSettingsChange(settings.copy(accessLogsEnabled = it)) }
    )
    ToggleRow(
        title = "自动选择节点",
        subtitle = "延迟检测可用后优先选择健康代理节点。",
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
        VpnStatus.Idle -> "未运行"
        VpnStatus.Starting -> "正在启动 VPN"
        VpnStatus.Running -> "VPN 运行中"
        VpnStatus.Failed -> "VPN 启动失败"
        VpnStatus.PermissionDenied -> "VPN 权限被拒绝"
    }
}

private enum class AppTab(val label: String, val icon: String) {
    Protection("防护", "防"),
    Rules("规则", "规"),
    Proxy("代理", "代"),
    Logs("日志", "志"),
    Settings("设置", "设")
}
