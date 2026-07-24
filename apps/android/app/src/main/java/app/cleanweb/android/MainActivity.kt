package app.cleanweb.android

import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.provider.OpenableColumns
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
import app.cleanweb.android.model.CleanWebState
import app.cleanweb.android.model.LogDecision
import app.cleanweb.android.model.ProxySubscription
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import app.cleanweb.android.model.RuleEntry
import app.cleanweb.android.model.RuleMatchKind
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
                val updateState = { nextState: CleanWebState, restartVpn: Boolean ->
                    appState = nextState
                    repository.save(nextState)
                    if (restartVpn && (status == VpnStatus.Running || status == VpnStatus.Starting)) {
                        CleanWebVpnService.restart(this@MainActivity)
                        status = VpnStatus.Starting
                        vpnError = null
                    }
                }
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
                val proxyConfigFileLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument()
                ) { uri: Uri? ->
                    if (uri == null) return@rememberLauncherForActivityResult
                    runCatching {
                        contentResolver.takePersistableUriPermission(
                            uri,
                            Intent.FLAG_GRANT_READ_URI_PERMISSION
                        )
                    }
                    val fileName = displayName(uri)
                    runCatching {
                        repository.importProxyConfigFile(
                            name = fileName.substringBeforeLast('.'),
                            fileName = fileName,
                            content = readTextDocument(uri)
                        )
                    }.onSuccess { subscription ->
                        updateState(
                            appState.copy(
                                proxySubscriptions = listOf(subscription) + appState.proxySubscriptions
                            ),
                            true
                        )
                    }.onFailure { error ->
                        appState = appState.withLog(
                            target = fileName,
                            decision = LogDecision.Warning,
                            reason = "配置文件导入失败：${error.message ?: error}"
                        )
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
                        updateState(appState.copy(settings = settings), true)
                    },
                    onAddRule = { pattern, category, action, matchKind ->
                        updateState(
                            appState.copy(
                                rules = listOf(
                                    RuleEntry(
                                        id = UUID.randomUUID().toString(),
                                        pattern = pattern,
                                        category = category,
                                        action = action,
                                        matchKind = matchKind
                                    )
                                ) + appState.rules
                            ),
                            true
                        )
                    },
                    onToggleRule = { ruleId ->
                        updateState(
                            appState.copy(
                                rules = appState.rules.map { rule ->
                                    if (rule.id == ruleId) rule.copy(enabled = !rule.enabled) else rule
                                }
                            ),
                            true
                        )
                    },
                    onRemoveRule = { ruleId ->
                        updateState(
                            appState.copy(rules = appState.rules.filterNot { it.id == ruleId }),
                            true
                        )
                    },
                    onAddProxySubscription = { name, url ->
                        updateState(
                            appState.copy(
                                proxySubscriptions = listOf(
                                    ProxySubscription(
                                        id = UUID.randomUUID().toString(),
                                        name = name,
                                        url = url
                                    )
                                ) + appState.proxySubscriptions
                            ),
                            true
                        )
                    },
                    onImportProxyConfigFile = {
                        proxyConfigFileLauncher.launch(
                            arrayOf(
                                "application/yaml",
                                "application/x-yaml",
                                "text/yaml",
                                "text/plain",
                                "application/octet-stream"
                            )
                        )
                    },
                    onToggleProxySubscription = { subscriptionId ->
                        updateState(
                            appState.copy(
                                proxySubscriptions = appState.proxySubscriptions.map { subscription ->
                                    if (subscription.id == subscriptionId) {
                                        subscription.copy(enabled = !subscription.enabled)
                                    } else {
                                        subscription
                                    }
                                }
                            ),
                            true
                        )
                    },
                    onRemoveProxySubscription = { subscriptionId ->
                        appState.proxySubscriptions
                            .firstOrNull { it.id == subscriptionId }
                            ?.let(repository::deleteLocalProvider)
                        updateState(
                            appState.copy(
                                proxySubscriptions = appState.proxySubscriptions.filterNot {
                                    it.id == subscriptionId
                                }
                            ),
                            true
                        )
                    },
                    onClearLogs = {
                        updateState(appState.copy(logs = emptyList()), false)
                    },
                    onAcknowledgeAlwaysOnGuidance = {
                        updateState(
                            appState.copy(
                                settings = appState.settings.copy(alwaysOnVpnGuidanceSeen = true)
                            ),
                            false
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
        private const val MAX_CONFIG_BYTES = 20 * 1024 * 1024
    }

    private fun displayName(uri: Uri): String {
        val cursor: Cursor? = contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            val index = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && it.moveToFirst()) {
                return it.getString(index)
            }
        }
        return uri.lastPathSegment?.substringAfterLast('/')?.ifBlank { null } ?: "proxy-config.yaml"
    }

    private fun readTextDocument(uri: Uri): String {
        val bytes = contentResolver.openInputStream(uri)?.use { input ->
            input.readBytes()
        } ?: throw IllegalArgumentException("无法读取配置文件")
        require(bytes.size <= MAX_CONFIG_BYTES) { "配置文件超过20MB限制" }
        return bytes.toString(Charsets.UTF_8)
    }
}
