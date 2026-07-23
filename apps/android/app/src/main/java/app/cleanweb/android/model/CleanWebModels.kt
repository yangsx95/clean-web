package app.cleanweb.android.model

data class CleanWebState(
    val settings: ProtectionSettings = ProtectionSettings(),
    val rules: List<RuleEntry> = defaultRules,
    val proxySubscriptions: List<ProxySubscription> = emptyList(),
    val logs: List<AccessLogEntry> = emptyList()
)

data class ProtectionSettings(
    val proxyEnabled: Boolean = false,
    val safeSearchEnabled: Boolean = true,
    val strictModeEnabled: Boolean = false,
    val adsTrackingEnabled: Boolean = true,
    val accessLogsEnabled: Boolean = true,
    val autoSelectNode: Boolean = true,
    val alwaysOnVpnGuidanceSeen: Boolean = false
)

data class RuleEntry(
    val id: String,
    val pattern: String,
    val category: RuleCategory,
    val action: RuleAction,
    val enabled: Boolean = true
)

enum class RuleCategory(val label: String) {
    Core("核心"),
    AdsTracking("广告"),
    CustomBlock("拦截"),
    CustomAllow("放行")
}

enum class RuleAction(val label: String) {
    Block("拦截"),
    Allow("放行")
}

data class ProxySubscription(
    val id: String,
    val name: String,
    val url: String,
    val enabled: Boolean = true,
    val importedNodeCount: Int = 0
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

val defaultRules = listOf(
    RuleEntry(
        id = "core-adult",
        pattern = "adult.example",
        category = RuleCategory.Core,
        action = RuleAction.Block
    ),
    RuleEntry(
        id = "core-gambling",
        pattern = "gambling.example",
        category = RuleCategory.Core,
        action = RuleAction.Block
    ),
    RuleEntry(
        id = "ads-tracking",
        pattern = "tracker.example",
        category = RuleCategory.AdsTracking,
        action = RuleAction.Block
    )
)
