package app.cleanweb.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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

private val PaperGround = Color(0xFFF6F4EF)
private val PaperCard = Color(0xFFFFFFFF)
private val PaperInk = Color(0xFF20262B)
private val PaperMuted = Color(0xFF5D6A70)
private val PaperLine = Color(0xFFD8DED9)
private val PaperSoft = Color(0xFFE8EEE9)
private val PaperAccent = Color(0xFF1F8A70)
private val PaperWarn = Color(0xFFC9853D)
private val PaperDanger = Color(0xFFD35B4B)

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
    val parentRules = appState.rules.filter(::isParentVisibleRule)

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = PaperGround
    ) {
        Scaffold(
            containerColor = PaperGround,
            bottomBar = {
                NavigationBar(
                    containerColor = PaperCard,
                    tonalElevation = 0.dp
                ) {
                    AppTab.entries.forEach { tab ->
                        NavigationBarItem(
                            selected = selectedTab == tab,
                            onClick = { selectedTab = tab },
                            icon = { Text(tab.icon, fontSize = 13.sp, fontWeight = FontWeight.Black) },
                            label = { Text(tab.label, fontSize = 11.sp, fontWeight = FontWeight.Bold) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = PaperCard,
                                selectedTextColor = PaperInk,
                                indicatorColor = PaperInk,
                                unselectedIconColor = PaperMuted,
                                unselectedTextColor = PaperMuted
                            )
                        )
                    }
                }
            }
        ) { padding ->
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 18.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item {
                    MobileHeader(tab = selectedTab, status = status)
                }

                when (selectedTab) {
                    AppTab.Protection -> protectionItems(
                        state = appState,
                        status = status,
                        vpnError = vpnError,
                        onStartProtection = onStartProtection,
                        onStopProtection = onStopProtection,
                        onSettingsChange = onSettingsChange,
                        onAcknowledgeAlwaysOnGuidance = onAcknowledgeAlwaysOnGuidance
                    )

                    AppTab.Rules -> {
                        item { RuleCategorySummary(appState.settings) }
                        item { RulesEditor(onAddRule) }
                        items(parentRules, key = { it.id }) { rule ->
                            RuleRow(rule, onToggleRule, onRemoveRule)
                        }
                        if (parentRules.isEmpty()) {
                            item { EmptyState("还没有添加家长规则") }
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
                            ProxyRow(subscription, onToggleProxySubscription, onRemoveProxySubscription)
                        }
                        if (appState.proxySubscriptions.isEmpty()) {
                            item { EmptyState("还没有导入代理订阅") }
                        }
                    }

                    AppTab.Logs -> {
                        item { LogsHeader(appState, onClearLogs) }
                        items(appState.logs, key = { it.id }) { log ->
                            LogRow(log)
                        }
                        if (appState.logs.isEmpty()) {
                            item { EmptyState("还没有本地访问事件") }
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

private fun androidx.compose.foundation.lazy.LazyListScope.protectionItems(
    state: CleanWebState,
    status: VpnStatus,
    vpnError: String?,
    onStartProtection: () -> Unit,
    onStopProtection: () -> Unit,
    onSettingsChange: (ProtectionSettings) -> Unit,
    onAcknowledgeAlwaysOnGuidance: () -> Unit
) {
    item {
        ProtectionHero(
            state = state,
            status = status,
            vpnError = vpnError,
            onStartProtection = onStartProtection,
            onStopProtection = onStopProtection
        )
    }
    item {
        StatStrip(state = state)
    }
    item {
        PolicySwitchPanel(
            settings = state.settings,
            onSettingsChange = onSettingsChange
        )
    }
    if (!state.settings.alwaysOnVpnGuidanceSeen) {
        item {
            PaperCard {
                SectionTitle("Android 权限")
                Text(
                    text = "启用后建议在系统 VPN 设置里开启始终开启 VPN 和无 VPN 时阻止连接。",
                    color = PaperMuted,
                    fontSize = 13.sp,
                    lineHeight = 18.sp
                )
                TextButton(onClick = onAcknowledgeAlwaysOnGuidance) {
                    Text("知道了", color = PaperAccent, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
private fun MobileHeader(tab: AppTab, status: VpnStatus) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Android", color = PaperMuted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text("CleanWeb", color = PaperInk, fontSize = 12.sp, fontWeight = FontWeight.Black)
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(tab.eyebrow, color = PaperAccent, fontSize = 11.sp, fontWeight = FontWeight.Black)
                Text(
                    tabTitle(tab, status),
                    color = PaperInk,
                    fontSize = 28.sp,
                    lineHeight = 32.sp,
                    fontWeight = FontWeight.Black
                )
            }
            StatusPill(statusLabel(status), dark = status == VpnStatus.Running || status == VpnStatus.Starting)
        }
    }
}

@Composable
private fun ProtectionHero(
    state: CleanWebState,
    status: VpnStatus,
    vpnError: String?,
    onStartProtection: () -> Unit,
    onStopProtection: () -> Unit
) {
    val protectionEnabled = status == VpnStatus.Running || status == VpnStatus.Starting
    PaperCard(containerColor = PaperInk) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (protectionEnabled) "Android VPN 已接管" else "CleanWeb 需要接管",
                    color = Color(0xFFDDE5E0),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(18.dp))
                Text(
                    text = when (status) {
                        VpnStatus.Running -> "所有策略已生效"
                        VpnStatus.Starting -> "正在启动保护"
                        VpnStatus.Failed -> "保护启动失败"
                        VpnStatus.PermissionDenied -> "需要 VPN 权限"
                        VpnStatus.Idle -> "保护未运行"
                    },
                    color = Color.White,
                    fontSize = 27.sp,
                    lineHeight = 31.sp,
                    fontWeight = FontWeight.Black
                )
                Text(
                    text = when (status) {
                        VpnStatus.Starting -> "Mihomo 和 tun2socks 正在准备数据通道。"
                        VpnStatus.Running -> "DNS 代理、本地拦截和代理路由按顺序执行。"
                        VpnStatus.Failed -> vpnError ?: "请查看日志里的启动失败原因。"
                        VpnStatus.PermissionDenied -> "请允许 Android VPN 权限后继续。"
                        VpnStatus.Idle -> "开启后设备流量将进入 CleanWeb VPN。"
                    },
                    color = Color(0xFFC8D0CC),
                    fontSize = 13.sp,
                    lineHeight = 18.sp,
                    maxLines = 4,
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
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            PrototypeButton(
                text = "开启",
                enabled = !protectionEnabled,
                primary = true,
                onClick = onStartProtection
            )
            PrototypeButton(
                text = "关闭",
                enabled = protectionEnabled,
                primary = false,
                onClick = onStopProtection
            )
        }
        SummaryRow("家长规则", state.rules.count { isParentVisibleRule(it) && it.enabled }.toString(), onDark = true)
        SummaryRow("过滤内核", "Mihomo + tun2socks", onDark = true)
    }
}

@Composable
private fun StatStrip(state: CleanWebState) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        StatCard("今日拦截", state.logs.count { it.decision == LogDecision.Blocked }.toString(), "拦截")
        StatCard("允许", state.logs.count { it.decision == LogDecision.Allowed }.toString(), "放行")
        StatCard("警告", state.logs.count { it.decision == LogDecision.Warning }.toString(), "异常")
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.StatCard(label: String, value: String, note: String) {
    PaperCard(
        modifier = Modifier.weight(1f),
        contentPadding = 12.dp
    ) {
        Text(label, color = PaperMuted, fontSize = 11.sp, fontWeight = FontWeight.Bold)
        Text(value, color = PaperInk, fontSize = 24.sp, lineHeight = 28.sp, fontWeight = FontWeight.Black)
        Text(note, color = PaperAccent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun PolicySwitchPanel(
    settings: ProtectionSettings,
    onSettingsChange: (ProtectionSettings) -> Unit
) {
    PaperCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            SectionTitle("策略开关")
            Text(
                listOf(
                    settings.safeSearchEnabled,
                    settings.strictModeEnabled,
                    settings.proxyEnabled,
                    settings.entertainmentEnabled,
                    settings.adsTrackingEnabled
                ).count { it }.toString() + " 项启用",
                color = PaperAccent,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold
            )
        }
        CompactToggle("安全搜索强制", "DNS 安全搜索映射", settings.safeSearchEnabled) {
            onSettingsChange(settings.copy(safeSearchEnabled = it))
        }
        CompactToggle("严格模式", "高风险后缀、关键词和 CIDR", settings.strictModeEnabled) {
            onSettingsChange(settings.copy(strictModeEnabled = it))
        }
        CompactToggle("代理订阅路由", "过滤之后再路由允许流量", settings.proxyEnabled) {
            onSettingsChange(settings.copy(proxyEnabled = it))
        }
        CompactToggle("短视频与游戏", "直播、短视频和游戏平台", settings.entertainmentEnabled) {
            onSettingsChange(settings.copy(entertainmentEnabled = it))
        }
    }
}

@Composable
private fun RuleCategorySummary(settings: ProtectionSettings) {
    PaperCard {
        SectionTitle("受保护类别")
        Text(
            text = "内置核心规则、订阅明细和严格模式补充规则由 CleanWeb 在后台维护，不在手机端逐条展示。",
            color = PaperMuted,
            fontSize = 12.sp,
            lineHeight = 17.sp
        )
        CategoryRow("色情与擦边", true, locked = true)
        CategoryRow("赌博、毒品、诈骗", true, locked = true)
        CategoryRow("恶意软件与钓鱼", true, locked = true)
        CategoryRow("短视频与游戏", settings.entertainmentEnabled, locked = false)
        CategoryRow("广告与跟踪", settings.adsTrackingEnabled, locked = false)
        if (settings.strictModeEnabled) {
            CategoryRow("严格模式补充", true, locked = false)
        }
    }
}

@Composable
private fun CategoryRow(label: String, enabled: Boolean, locked: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .clip(CircleShape)
                    .background(if (enabled) PaperAccent else PaperWarn)
            )
            Spacer(Modifier.width(10.dp))
            Text(label, color = PaperInk, fontSize = 14.sp, fontWeight = FontWeight.Bold)
        }
        Text(
            text = if (locked) "强制" else if (enabled) "开启" else "关闭",
            color = if (enabled) PaperAccent else PaperMuted,
            fontSize = 12.sp,
            fontWeight = FontWeight.Black
        )
    }
}

@Composable
private fun RulesEditor(onAddRule: (String, RuleCategory, RuleAction, RuleMatchKind) -> Unit) {
    var pattern by remember { mutableStateOf("") }
    var action by remember { mutableStateOf(RuleAction.Block) }
    var matchKind by remember { mutableStateOf(RuleMatchKind.Suffix) }

    PaperCard {
        SectionTitle("添加家长规则")
        OutlinedTextField(
            modifier = Modifier.fillMaxWidth(),
            value = pattern,
            onValueChange = { pattern = it.trim() },
            label = { Text("example.com 或 47.96.0.0/12") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None)
        )
        ButtonRow {
            RuleAction.entries.forEach { item ->
                SmallChoice(item.label, selected = action == item) { action = item }
            }
        }
        ButtonRow {
            listOf(RuleMatchKind.Suffix, RuleMatchKind.Exact).forEach { item ->
                SmallChoice(item.label, selected = matchKind == item) { matchKind = item }
            }
        }
        ButtonRow {
            listOf(RuleMatchKind.Keyword, RuleMatchKind.Cidr).forEach { item ->
                SmallChoice(item.label, selected = matchKind == item) { matchKind = item }
            }
        }
        PrototypeButton(
            text = "添加规则",
            enabled = pattern.isNotBlank(),
            primary = true,
            onClick = {
                onAddRule(
                    pattern,
                    when (action) {
                        RuleAction.Block -> RuleCategory.CustomBlock
                        RuleAction.Allow -> RuleCategory.CustomAllow
                        RuleAction.Proxy -> RuleCategory.Routing
                        RuleAction.SystemRoute -> RuleCategory.Routing
                    },
                    action,
                    matchKind
                )
                pattern = ""
                action = RuleAction.Block
                matchKind = RuleMatchKind.Suffix
            }
        )
    }
}

@Composable
private fun RuleRow(
    rule: RuleEntry,
    onToggleRule: (String) -> Unit,
    onRemoveRule: (String) -> Unit
) {
    PaperCard(contentPadding = 14.dp) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(rule.pattern, color = PaperInk, fontSize = 15.sp, fontWeight = FontWeight.Black, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    "${rule.action.label} · ${rule.category.label} · ${rule.matchKind.label}",
                    color = PaperMuted,
                    fontSize = 12.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Switch(checked = rule.enabled, onCheckedChange = { onToggleRule(rule.id) })
        }
        if (!rule.id.startsWith("core-")) {
            TextButton(onClick = { onRemoveRule(rule.id) }) {
                Text("删除", color = PaperDanger, fontWeight = FontWeight.Bold)
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

    PaperCard {
        SectionTitle("导入代理")
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
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PrototypeButton(
                text = "导入 URL",
                enabled = name.isNotBlank() && url.startsWith("https://"),
                primary = true,
                onClick = {
                    onAddProxySubscription(name.trim(), url)
                    name = ""
                    url = ""
                }
            )
            PrototypeButton("配置文件", enabled = true, primary = false, onClick = onImportProxyConfigFile)
        }
        Text(
            text = "只保留代理节点和代理组，DNS、TUN、脚本和绕过规则都会被丢弃。",
            color = PaperMuted,
            fontSize = 12.sp,
            lineHeight = 17.sp
        )
    }
}

@Composable
private fun ProxyRow(
    subscription: ProxySubscription,
    onToggleProxySubscription: (String) -> Unit,
    onRemoveProxySubscription: (String) -> Unit
) {
    PaperCard(contentPadding = 14.dp) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(subscription.name, color = PaperInk, fontSize = 15.sp, fontWeight = FontWeight.Black)
                Text(
                    if (subscription.localProviderFileName == null) subscription.url else "本地配置文件 · ${subscription.importedNodeCount} 个节点",
                    color = PaperMuted,
                    fontSize = 12.sp,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Switch(checked = subscription.enabled, onCheckedChange = { onToggleProxySubscription(subscription.id) })
        }
        TextButton(onClick = { onRemoveProxySubscription(subscription.id) }) {
            Text("删除", color = PaperDanger, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun LogsHeader(state: CleanWebState, onClearLogs: () -> Unit) {
    PaperCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                SectionTitle("本地日志")
                Text(
                    if (state.settings.accessLogsEnabled) "最终访问决策仅保存在本机" else "本地日志已关闭",
                    color = PaperMuted,
                    fontSize = 12.sp
                )
            }
            PrototypeButton("清空", enabled = true, primary = false, onClick = onClearLogs)
        }
    }
}

@Composable
private fun LogRow(log: AccessLogEntry) {
    PaperCard(contentPadding = 14.dp) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(log.timeLabel, color = PaperMuted, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            DecisionPill(log.decision)
        }
        Text(log.target, color = PaperInk, fontSize = 15.sp, fontWeight = FontWeight.Black, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(log.reason, color = PaperMuted, fontSize = 12.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun SettingsPanel(
    settings: ProtectionSettings,
    onSettingsChange: (ProtectionSettings) -> Unit
) {
    PaperCard {
        SectionTitle("设置")
        CompactToggle("代理路由", "允许的流量使用导入节点", settings.proxyEnabled) {
            onSettingsChange(settings.copy(proxyEnabled = it))
        }
        CompactToggle("严格模式", "更激进的高风险规则", settings.strictModeEnabled) {
            onSettingsChange(settings.copy(strictModeEnabled = it))
        }
        CompactToggle("广告与跟踪", "可选广告和跟踪器类别", settings.adsTrackingEnabled) {
            onSettingsChange(settings.copy(adsTrackingEnabled = it))
        }
        CompactToggle("短视频与游戏", "短视频、直播和游戏平台", settings.entertainmentEnabled) {
            onSettingsChange(settings.copy(entertainmentEnabled = it))
        }
        CompactToggle("访问日志", "本机保存访问决策", settings.accessLogsEnabled) {
            onSettingsChange(settings.copy(accessLogsEnabled = it))
        }
        CompactToggle("自动选择节点", "优先使用健康代理节点", settings.autoSelectNode) {
            onSettingsChange(settings.copy(autoSelectNode = it))
        }
    }
}

@Composable
private fun CompactToggle(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .clip(CircleShape)
                    .background(if (checked) PaperAccent else PaperWarn)
            )
            Spacer(Modifier.width(10.dp))
            Column {
                Text(title, color = PaperInk, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                Text(subtitle, color = PaperMuted, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun SummaryRow(label: String, value: String, onDark: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = if (onDark) Color(0xFFC8D0CC) else PaperMuted, fontSize = 12.sp)
        Text(value, color = if (onDark) Color.White else PaperInk, fontSize = 12.sp, fontWeight = FontWeight.Black)
    }
    HorizontalDivider(color = if (onDark) Color(0xFF3A4247) else PaperLine)
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, color = PaperInk, fontSize = 16.sp, fontWeight = FontWeight.Black)
}

@Composable
private fun StatusPill(text: String, dark: Boolean) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (dark) PaperInk else PaperCard)
            .border(1.dp, if (dark) PaperInk else PaperLine, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Text(text, color = if (dark) Color.White else PaperInk, fontSize = 12.sp, fontWeight = FontWeight.Black)
    }
}

@Composable
private fun DecisionPill(decision: LogDecision) {
    val color = when (decision) {
        LogDecision.Blocked -> PaperDanger
        LogDecision.Warning -> PaperWarn
        LogDecision.Allowed -> PaperAccent
    }
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(999.dp))
            .background(color.copy(alpha = 0.12f))
            .padding(horizontal = 9.dp, vertical = 4.dp)
    ) {
        Text(decision.label, color = color, fontSize = 11.sp, fontWeight = FontWeight.Black)
    }
}

@Composable
private fun ButtonRow(content: @Composable () -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        content()
    }
}

@Composable
private fun SmallChoice(text: String, selected: Boolean, onClick: () -> Unit) {
    OutlinedButton(
        onClick = onClick,
        shape = RoundedCornerShape(8.dp),
        colors = ButtonDefaults.outlinedButtonColors(
            containerColor = if (selected) PaperInk else PaperCard,
            contentColor = if (selected) Color.White else PaperInk
        )
    ) {
        Text(text, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun PrototypeButton(
    text: String,
    enabled: Boolean,
    primary: Boolean,
    onClick: () -> Unit
) {
    val colors = if (primary) {
        ButtonDefaults.buttonColors(containerColor = PaperAccent, contentColor = Color.White)
    } else {
        ButtonDefaults.outlinedButtonColors(containerColor = PaperCard, contentColor = PaperInk)
    }
    if (primary) {
        Button(
            enabled = enabled,
            onClick = onClick,
            shape = RoundedCornerShape(8.dp),
            colors = colors
        ) {
            Text(text, fontSize = 13.sp, fontWeight = FontWeight.Black)
        }
    } else {
        OutlinedButton(
            enabled = enabled,
            onClick = onClick,
            shape = RoundedCornerShape(8.dp),
            colors = colors
        ) {
            Text(text, fontSize = 13.sp, fontWeight = FontWeight.Black)
        }
    }
}

@Composable
private fun EmptyState(message: String) {
    PaperCard {
        Text(message, color = PaperMuted, fontSize = 13.sp)
    }
}

@Composable
private fun PaperCard(
    modifier: Modifier = Modifier,
    containerColor: Color = PaperCard,
    contentPadding: androidx.compose.ui.unit.Dp = 16.dp,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        border = if (containerColor == PaperCard) androidx.compose.foundation.BorderStroke(1.dp, PaperLine) else null
    ) {
        Column(
            modifier = Modifier.padding(contentPadding),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            content = content
        )
    }
}

private fun statusLabel(status: VpnStatus): String {
    return when (status) {
        VpnStatus.Idle -> "未运行"
        VpnStatus.Starting -> "启动中"
        VpnStatus.Running -> "运行中"
        VpnStatus.Failed -> "失败"
        VpnStatus.PermissionDenied -> "需授权"
    }
}

private fun isParentVisibleRule(rule: RuleEntry): Boolean {
    return rule.category == RuleCategory.CustomBlock ||
        rule.category == RuleCategory.CustomAllow ||
        rule.category == RuleCategory.Routing
}

private fun tabTitle(tab: AppTab, status: VpnStatus): String {
    if (tab != AppTab.Protection) {
        return tab.title
    }
    return when (status) {
        VpnStatus.Running -> "保护运行中"
        VpnStatus.Starting -> "正在启动"
        VpnStatus.Failed -> "保护失效"
        VpnStatus.PermissionDenied -> "启用 VPN 保护"
        VpnStatus.Idle -> "启用 VPN 保护"
    }
}

private enum class AppTab(val label: String, val icon: String, val eyebrow: String, val title: String) {
    Protection("概览", "●", "网络保护", "保护运行中"),
    Rules("规则", "▣", "规则管理", "家长规则"),
    Proxy("代理", "◈", "代理节点", "代理订阅"),
    Logs("日志", "◇", "本地日志", "访问日志"),
    Settings("设置", "○", "系统设置", "保护设置")
}
