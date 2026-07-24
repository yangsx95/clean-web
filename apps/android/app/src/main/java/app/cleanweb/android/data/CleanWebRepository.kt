package app.cleanweb.android.data

import android.content.Context
import app.cleanweb.android.model.AccessLogEntry
import app.cleanweb.android.model.CleanWebState
import app.cleanweb.android.model.LogDecision
import app.cleanweb.android.model.ProtectionSettings
import app.cleanweb.android.model.ProxySubscription
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import app.cleanweb.android.model.RuleEntry
import app.cleanweb.android.model.RuleMatchKind
import app.cleanweb.android.model.defaultRules
import org.json.JSONArray
import org.json.JSONObject

class CleanWebRepository(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun load(): CleanWebState {
        val settings = preferences.getString(KEY_SETTINGS, null)?.let(::settingsFromJson)
            ?: ProtectionSettings()
        val rules = preferences.getString(KEY_RULES, null)?.let(::rulesFromJson)
            ?: defaultRules
        val proxySubscriptions =
            preferences.getString(KEY_PROXY_SUBSCRIPTIONS, null)?.let(::proxySubscriptionsFromJson)
                ?: emptyList()
        val logs = preferences.getString(KEY_LOGS, null)?.let(::logsFromJson) ?: emptyList()
        return CleanWebState(
            settings = settings,
            rules = rules,
            proxySubscriptions = proxySubscriptions,
            logs = logs
        )
    }

    fun save(state: CleanWebState) {
        preferences.edit()
            .putString(KEY_SETTINGS, state.settings.toJson().toString())
            .putString(KEY_RULES, rulesToJson(state.rules).toString())
            .putString(KEY_PROXY_SUBSCRIPTIONS, proxySubscriptionsToJson(state.proxySubscriptions).toString())
            .putString(KEY_LOGS, logsToJson(state.logs).toString())
            .apply()
    }

    fun appendLog(entry: AccessLogEntry, maxEntries: Int = 50) {
        val state = load()
        if (!state.settings.accessLogsEnabled) {
            return
        }
        save(state.copy(logs = (listOf(entry) + state.logs).take(maxEntries)))
    }

    private fun settingsFromJson(raw: String): ProtectionSettings {
        return runCatching {
            val value = JSONObject(raw)
            ProtectionSettings(
                proxyEnabled = value.optBoolean("proxyEnabled", false),
                safeSearchEnabled = value.optBoolean("safeSearchEnabled", true),
                strictModeEnabled = value.optBoolean("strictModeEnabled", false),
                adsTrackingEnabled = value.optBoolean("adsTrackingEnabled", true),
                accessLogsEnabled = value.optBoolean("accessLogsEnabled", true),
                autoSelectNode = value.optBoolean("autoSelectNode", true),
                alwaysOnVpnGuidanceSeen = value.optBoolean("alwaysOnVpnGuidanceSeen", false)
            )
        }.getOrDefault(ProtectionSettings())
    }

    private fun rulesFromJson(raw: String): List<RuleEntry> {
        return runCatching {
            val values = JSONArray(raw)
            List(values.length()) { index ->
                val value = values.getJSONObject(index)
                RuleEntry(
                    id = value.getString("id"),
                    pattern = value.getString("pattern"),
                    category = enumValueOf(value.getString("category")),
                    action = enumValueOf(value.getString("action")),
                    matchKind = value.takeIf { it.has("matchKind") }
                        ?.getString("matchKind")
                        ?.let { raw -> runCatching { enumValueOf<RuleMatchKind>(raw) }.getOrNull() }
                        ?: inferMatchKind(value.getString("pattern")),
                    enabled = value.optBoolean("enabled", true)
                )
            }.ifEmpty { defaultRules }
        }.getOrDefault(defaultRules)
    }

    private fun proxySubscriptionsFromJson(raw: String): List<ProxySubscription> {
        return runCatching {
            val values = JSONArray(raw)
            List(values.length()) { index ->
                val value = values.getJSONObject(index)
                ProxySubscription(
                    id = value.getString("id"),
                    name = value.getString("name"),
                    url = value.getString("url"),
                    enabled = value.optBoolean("enabled", true),
                    importedNodeCount = value.optInt("importedNodeCount", 0)
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun logsFromJson(raw: String): List<AccessLogEntry> {
        return runCatching {
            val values = JSONArray(raw)
            List(values.length()) { index ->
                val value = values.getJSONObject(index)
                AccessLogEntry(
                    id = value.getString("id"),
                    timeLabel = value.getString("timeLabel"),
                    target = value.getString("target"),
                    decision = enumValueOf(value.getString("decision")),
                    reason = value.getString("reason")
                )
            }
        }.getOrDefault(emptyList())
    }

    private fun ProtectionSettings.toJson(): JSONObject {
        return JSONObject()
            .put("proxyEnabled", proxyEnabled)
            .put("safeSearchEnabled", safeSearchEnabled)
            .put("strictModeEnabled", strictModeEnabled)
            .put("adsTrackingEnabled", adsTrackingEnabled)
            .put("accessLogsEnabled", accessLogsEnabled)
            .put("autoSelectNode", autoSelectNode)
            .put("alwaysOnVpnGuidanceSeen", alwaysOnVpnGuidanceSeen)
    }

    private fun rulesToJson(rules: List<RuleEntry>): JSONArray {
        return JSONArray().also { values ->
            rules.forEach { rule ->
                values.put(
                    JSONObject()
                        .put("id", rule.id)
                        .put("pattern", rule.pattern)
                        .put("category", rule.category.name)
                        .put("action", rule.action.name)
                        .put("matchKind", rule.matchKind.name)
                        .put("enabled", rule.enabled)
                )
            }
        }
    }

    private fun proxySubscriptionsToJson(subscriptions: List<ProxySubscription>): JSONArray {
        return JSONArray().also { values ->
            subscriptions.forEach { subscription ->
                values.put(
                    JSONObject()
                        .put("id", subscription.id)
                        .put("name", subscription.name)
                        .put("url", subscription.url)
                        .put("enabled", subscription.enabled)
                        .put("importedNodeCount", subscription.importedNodeCount)
                )
            }
        }
    }

    private fun logsToJson(logs: List<AccessLogEntry>): JSONArray {
        return JSONArray().also { values ->
            logs.forEach { log ->
                values.put(
                    JSONObject()
                        .put("id", log.id)
                        .put("timeLabel", log.timeLabel)
                        .put("target", log.target)
                        .put("decision", log.decision.name)
                        .put("reason", log.reason)
                )
            }
        }
    }

    companion object {
        private const val PREFERENCES_NAME = "cleanweb_android"
        private const val KEY_SETTINGS = "settings"
        private const val KEY_RULES = "rules"
        private const val KEY_PROXY_SUBSCRIPTIONS = "proxy_subscriptions"
        private const val KEY_LOGS = "logs"
    }
}

private fun inferMatchKind(pattern: String): RuleMatchKind {
    return if (pattern.contains("/")) RuleMatchKind.Cidr else RuleMatchKind.Suffix
}
