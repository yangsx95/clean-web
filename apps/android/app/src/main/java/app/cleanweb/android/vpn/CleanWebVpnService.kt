package app.cleanweb.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import app.cleanweb.android.R
import app.cleanweb.android.data.CleanWebRepository
import app.cleanweb.android.model.AccessLogEntry
import app.cleanweb.android.model.LogDecision
import engine.Engine
import engine.Key
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

class CleanWebVpnService : VpnService() {
    private var tunInterface: ParcelFileDescriptor? = null
    private var mihomoRunner: MihomoAndroidRunner? = null
    private val running = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopVpn()
            else -> {
                currentStatus = VpnStatus.Starting
                lastError = null
                startVpn()
            }
        }
        return Service.START_STICKY
    }

    override fun onDestroy() {
        stopVpn(updateStatus = currentStatus != VpnStatus.Failed)
        super.onDestroy()
    }

    private fun startVpn() {
        if (tunInterface != null) {
            return
        }

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        val repository = CleanWebRepository(applicationContext)
        val state = repository.load()
        val runner = MihomoAndroidRunner(applicationContext)

        val logFile = try {
            runner.start(state)
        } catch (error: Exception) {
            val message = "安卓内核启动失败：${error.message}"
            repository.appendLog(
                accessLog(
                    target = "Mihomo",
                    decision = LogDecision.Warning,
                    reason = message
                )
            )
            failVpn(message)
            return
        }
        mihomoRunner = runner

        tunInterface = try {
            Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(VPN_MTU)
                .addAddress("172.19.0.1", 30)
                .addDnsServer("223.5.5.5")
                .addDnsServer("119.29.29.29")
                .addRoute("0.0.0.0", 0)
                .apply {
                    runCatching { addDisallowedApplication(packageName) }
                }
                .establish()
        } catch (error: Exception) {
            val message = "安卓 VPN 接口创建失败：${error.message}"
            repository.appendLog(
                accessLog(
                    target = "安卓 VPN",
                    decision = LogDecision.Warning,
                    reason = message
                )
            )
            failVpn(message)
            return
        }

        tunInterface?.let { descriptor ->
            running.set(true)
            val fd = descriptor.detachFd()
            try {
                startTun2Socks(fd)
                isRunning = true
                currentStatus = VpnStatus.Running
                lastError = null
                repository.appendLog(
                    accessLog(
                        target = "Mihomo",
                        decision = LogDecision.Allowed,
                        reason = "全设备隧道已启动。日志：${logFile.name}"
                    )
                )
            } catch (error: Exception) {
                val message = "全设备隧道启动失败：${error.message}"
                repository.appendLog(
                    accessLog(
                        target = "tun2socks",
                        decision = LogDecision.Warning,
                        reason = message
                    )
                )
                failVpn(message)
            }
        }
        if (tunInterface == null) {
            val message = "安卓 VPN 接口创建失败。"
            repository.appendLog(
                accessLog(
                    target = "安卓 VPN",
                    decision = LogDecision.Warning,
                    reason = message
                )
            )
            failVpn(message)
        }
    }

    private fun failVpn(message: String) {
        running.set(false)
        runCatching { Engine.stop() }
        mihomoRunner?.stop()
        mihomoRunner = null
        tunInterface?.close()
        tunInterface = null
        isRunning = false
        currentStatus = VpnStatus.Failed
        lastError = message
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun stopVpn(updateStatus: Boolean = true) {
        running.set(false)
        runCatching { Engine.stop() }
        mihomoRunner?.stop()
        mihomoRunner = null
        tunInterface?.close()
        tunInterface = null
        isRunning = false
        if (updateStatus) {
            currentStatus = VpnStatus.Idle
            lastError = null
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startTun2Socks(fd: Int) {
        val key = Key().apply {
            setMTU(VPN_MTU.toLong())
            setDevice("fd://$fd")
            setProxy("socks5://127.0.0.1:17890")
            setRestAPI("")
            setLogLevel("info")
            setInterface("")
            setTCPModerateReceiveBuffer(true)
            setTCPSendBufferSize("")
            setTCPReceiveBufferSize("")
        }
        Engine.insert(key)
        Engine.start()
    }

    private fun accessLog(
        target: String,
        decision: LogDecision,
        reason: String
    ): AccessLogEntry {
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        return AccessLogEntry(
            id = UUID.randomUUID().toString(),
            timeLabel = timestamp,
            target = target,
            decision = decision,
            reason = reason
        )
    }

    private fun buildNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }

        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    companion object {
        private const val ACTION_STOP = "app.cleanweb.android.vpn.STOP"
        private const val CHANNEL_ID = "cleanweb_vpn"
        private const val NOTIFICATION_ID = 1001
        private const val VPN_MTU = 1500

        @Volatile
        var isRunning: Boolean = false
            private set

        @Volatile
        var currentStatus: VpnStatus = VpnStatus.Idle
            private set

        @Volatile
        var lastError: String? = null
            private set

        fun start(context: Context) {
            currentStatus = VpnStatus.Starting
            lastError = null
            val intent = Intent(context, CleanWebVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, CleanWebVpnService::class.java).setAction(ACTION_STOP)
            )
        }
    }
}
