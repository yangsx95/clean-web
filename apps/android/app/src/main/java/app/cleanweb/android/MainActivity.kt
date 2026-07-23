package app.cleanweb.android

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import app.cleanweb.android.data.CleanWebRepository
import app.cleanweb.android.model.AccessLogEntry
import app.cleanweb.android.model.LogDecision
import app.cleanweb.android.model.ProxySubscription
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import app.cleanweb.android.model.RuleEntry
import app.cleanweb.android.ui.CleanWebApp
import app.cleanweb.android.ui.theme.CleanWebTheme
import app.cleanweb.android.vpn.CleanWebVpnService
import app.cleanweb.android.vpn.VpnStatus
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            CleanWebTheme {
                val repository = remember { CleanWebRepository(applicationContext) }
                var appState by remember { mutableStateOf(repository.load()) }
                var status by remember { mutableStateOf(VpnStatus.Idle) }
                val vpnPermissionLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.StartActivityForResult()
                ) { result ->
                    if (result.resultCode == RESULT_OK) {
                        CleanWebVpnService.start(this)
                        status = VpnStatus.Starting
                        appState = appState.withLog(
                            target = "Android VPN",
                            decision = LogDecision.Warning,
                            reason = "Full-device tunnel is starting."
                        )
                    } else {
                        status = VpnStatus.PermissionDenied
                    }
                }

                LaunchedEffect(Unit) {
                    status = if (CleanWebVpnService.isRunning) VpnStatus.Running else VpnStatus.Idle
                }

                LaunchedEffect(appState) {
                    repository.save(appState)
                }

                LaunchedEffect(status) {
                    while (true) {
                        delay(2_000)
                        status = when {
                            CleanWebVpnService.isRunning -> VpnStatus.Running
                            status == VpnStatus.PermissionDenied -> VpnStatus.PermissionDenied
                            else -> VpnStatus.Idle
                        }
                        val latest = repository.load()
                        if (latest != appState) {
                            appState = latest
                        }
                    }
                }

                CleanWebApp(
                    appState = appState,
                    status = status,
                    onStartProtection = {
                        val permissionIntent: Intent? = VpnService.prepare(this)
                        if (permissionIntent == null) {
                            CleanWebVpnService.start(this)
                            status = VpnStatus.Starting
                            appState = appState.withLog(
                                target = "Android VPN",
                                decision = LogDecision.Warning,
                                reason = "Full-device tunnel is starting."
                            )
                        } else {
                            vpnPermissionLauncher.launch(permissionIntent)
                        }
                    },
                    onStopProtection = {
                        CleanWebVpnService.stop(this)
                        status = VpnStatus.Idle
                        appState = appState.withLog(
                            target = "Android VPN",
                            decision = LogDecision.Allowed,
                            reason = "VPN service stopped by administrator."
                        )
                    },
                    onSettingsChange = { settings ->
                        appState = appState.copy(settings = settings)
                    },
                    onAddRule = { pattern, category, action ->
                        appState = appState.copy(
                            rules = listOf(
                                RuleEntry(
                                    id = UUID.randomUUID().toString(),
                                    pattern = pattern,
                                    category = category,
                                    action = action
                                )
                            ) + appState.rules
                        )
                    },
                    onToggleRule = { ruleId ->
                        appState = appState.copy(
                            rules = appState.rules.map { rule ->
                                if (rule.id == ruleId) rule.copy(enabled = !rule.enabled) else rule
                            }
                        )
                    },
                    onRemoveRule = { ruleId ->
                        appState = appState.copy(rules = appState.rules.filterNot { it.id == ruleId })
                    },
                    onAddProxySubscription = { name, url ->
                        appState = appState.copy(
                            proxySubscriptions = listOf(
                                ProxySubscription(
                                    id = UUID.randomUUID().toString(),
                                    name = name,
                                    url = url
                                )
                            ) + appState.proxySubscriptions
                        )
                    },
                    onToggleProxySubscription = { subscriptionId ->
                        appState = appState.copy(
                            proxySubscriptions = appState.proxySubscriptions.map { subscription ->
                                if (subscription.id == subscriptionId) {
                                    subscription.copy(enabled = !subscription.enabled)
                                } else {
                                    subscription
                                }
                            }
                        )
                    },
                    onRemoveProxySubscription = { subscriptionId ->
                        appState = appState.copy(
                            proxySubscriptions = appState.proxySubscriptions.filterNot {
                                it.id == subscriptionId
                            }
                        )
                    },
                    onClearLogs = {
                        appState = appState.copy(logs = emptyList())
                    },
                    onAcknowledgeAlwaysOnGuidance = {
                        appState = appState.copy(
                            settings = appState.settings.copy(alwaysOnVpnGuidanceSeen = true)
                        )
                    }
                )
            }
        }
    }

    private fun app.cleanweb.android.model.CleanWebState.withLog(
        target: String,
        decision: LogDecision,
        reason: String
    ): app.cleanweb.android.model.CleanWebState {
        if (!settings.accessLogsEnabled) {
            return this
        }
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        val entry = AccessLogEntry(
            id = UUID.randomUUID().toString(),
            timeLabel = timestamp,
            target = target,
            decision = decision,
            reason = reason
        )
        return copy(logs = (listOf(entry) + logs).take(MAX_LOCAL_LOGS))
    }

    companion object {
        private const val MAX_LOCAL_LOGS = 50
    }
}
