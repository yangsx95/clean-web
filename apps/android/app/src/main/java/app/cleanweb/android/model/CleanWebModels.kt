package app.cleanweb.android.model

data class CleanWebState(
    val settings: ProtectionSettings = ProtectionSettings(),
    val rules: List<RuleEntry> = emptyList(),
    val strictModeRules: List<RuleEntry> = emptyList(),
    val proxySubscriptions: List<ProxySubscription> = emptyList(),
    val logs: List<AccessLogEntry> = emptyList()
)

data class ProtectionSettings(
    val proxyEnabled: Boolean = false,
    val safeSearchEnabled: Boolean = true,
    val strictModeEnabled: Boolean = false,
    val adsTrackingEnabled: Boolean = true,
    val entertainmentEnabled: Boolean = false,
    val accessLogsEnabled: Boolean = true,
    val autoSelectNode: Boolean = true,
    val alwaysOnVpnGuidanceSeen: Boolean = false
)

data class RuleEntry(
    val id: String,
    val pattern: String,
    val category: RuleCategory,
    val action: RuleAction,
    val matchKind: RuleMatchKind = RuleMatchKind.Suffix,
    val enabled: Boolean = true
)

enum class RuleCategory(val label: String) {
    Core("核心"),
    AdsTracking("广告"),
    Entertainment("短视频与游戏"),
    CustomBlock("拦截"),
    CustomAllow("放行"),
    Routing("路由")
}

enum class RuleAction(val label: String) {
    Block("拦截"),
    Allow("直连"),
    Proxy("走代理"),
    SystemRoute("系统路由")
}

enum class RuleMatchKind(val label: String) {
    Suffix("域名及子域名"),
    Exact("精确域名"),
    Keyword("关键词"),
    Cidr("IP/CIDR")
}

data class ProxySubscription(
    val id: String,
    val name: String,
    val url: String,
    val enabled: Boolean = true,
    val importedNodeCount: Int = 0,
    val localProviderFileName: String? = null
)

data class AccessLogEntry(
    val id: String,
    val timeLabel: String,
    val target: String,
    val decision: LogDecision,
    val reason: String
)

enum class LogDecision(val label: String) {
    Allowed("允许"),
    Blocked("拦截"),
    Warning("警告")
}

val legacyPlaceholderRuleIds = setOf("core-adult", "core-gambling", "ads-tracking")

fun normalizeBuiltInRules(rules: List<RuleEntry>, builtInRules: List<RuleEntry>): List<RuleEntry> {
    val userRules = rules.filterNot { rule ->
        rule.id in legacyPlaceholderRuleIds || builtInRules.any { it.id == rule.id }
    }
    return builtInRules + userRules
}
