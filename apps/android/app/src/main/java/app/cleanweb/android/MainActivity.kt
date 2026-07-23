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
                var vpnError by remember { mutableStateOf<String?>(null) }
                val vpnPermissionLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.StartActivityForResult()
                ) { result ->
                    if (result.resultCode == RESULT_OK) {
                        CleanWebVpnService.start(this)
                        status = VpnStatus.Starting
                        vpnError = null
                        appState = appState.withLog(
                            target = "安卓 VPN",
                            decision = LogDecision.Warning,
                            reason = "全设备隧道正在启动。"
                        )
                    } else {
                        status = VpnStatus.PermissionDenied
                    }
                }

                LaunchedEffect(appState) {
                    repository.save(appState)
                }

                LaunchedEffect(Unit) {
                    while (true) {
                        val serviceStatus = when {
                            CleanWebVpnService.currentStatus == VpnStatus.Running -> VpnStatus.Running
                            CleanWebVpnService.currentStatus == VpnStatus.Starting -> VpnStatus.Starting
                            CleanWebVpnService.currentStatus == VpnStatus.Failed -> VpnStatus.Failed
                            status == VpnStatus.PermissionDenied -> VpnStatus.PermissionDenied
                            else -> VpnStatus.Idle
                        }
                        status = serviceStatus
                        vpnError = CleanWebVpnService.lastError
                        val latest = repository.load()
                        if (latest != appState) {
                            appState = latest
                        }
                        delay(2_000)
                    }
                }

                CleanWebApp(
                    appState = appState,
                    status = status,
                    vpnError = vpnError,
                    onStartProtection = {
                        val permissionIntent: Intent? = VpnService.prepare(this)
                        if (permissionIntent == null) {
                            CleanWebVpnService.start(this)
                            status = VpnStatus.Starting
                            vpnError = null
                            appState = appState.withLog(
                                target = "安卓 VPN",
                                decision = LogDecision.Warning,
                                reason = "全设备隧道正在启动。"
                            )
                        } else {
                            vpnPermissionLauncher.launch(permissionIntent)
                        }
                    },
                    onStopProtection = {
                        CleanWebVpnService.stop(this)
                        status = VpnStatus.Idle
                        vpnError = null
                        appState = appState.withLog(
                            target = "安卓 VPN",
                            decision = LogDecision.Allowed,
                            reason = "管理员已停止 VPN 服务。"
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
