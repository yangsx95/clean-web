package app.cleanweb.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.File
import java.net.DatagramSocket
import java.net.InetAddress

class CleanWebVpnService : VpnService() {
  private var vpnInterface: ParcelFileDescriptor? = null
  private var mihomoProcess: Process? = null
  @Volatile
  private var packetLoopRunning = false
  @Volatile
  private var stopping = false
  private var packetThread: Thread? = null
  private var mihomoLogThread: Thread? = null
  private var upstreamDnsServers: List<InetAddress> = emptyList()

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_STOP -> stopVpn()
      else -> {
        startForeground(NOTIFICATION_ID, buildNotification("Starting DNS filtering protection"))
        startVpn()
      }
    }
    return START_STICKY
  }

  override fun onDestroy() {
    stopVpn(false)
    super.onDestroy()
  }

  override fun onRevoke() {
    stopVpn()
    super.onRevoke()
  }

  private fun startVpn() {
    if (vpnInterface != null) {
      CleanWebVpnState.markRunning()
      return
    }

    try {
      stopping = false
      CleanWebVpnState.markStarting()
      CleanWebVpnState.loadPolicy(this)
      upstreamDnsServers = captureUpstreamDnsServers()
      startForeground(NOTIFICATION_ID, buildNotification("DNS filtering protection is running"))

      val builder = Builder()
        .setSession("CleanWeb")
        .setMtu(1500)
        .addAddress("10.255.0.2", 32)
        .addDnsServer(if (CleanWebVpnState.mihomoEnabled) "1.1.1.1" else CLEANWEB_DNS_ADDRESS)
        .addRoute(if (CleanWebVpnState.mihomoEnabled) "0.0.0.0" else CLEANWEB_DNS_ADDRESS, if (CleanWebVpnState.mihomoEnabled) 0 else 32)
        .setConfigureIntent(configureIntent())

      if (CleanWebVpnState.mihomoEnabled) {
        try {
          builder.addDisallowedApplication(packageName)
        } catch (error: Exception) {
          throw IllegalStateException("CleanWeb app could not be excluded from Android VPN loop: ${error.message}")
        }
      }

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        builder.setMetered(false)
      }

      vpnInterface = builder.establish() ?: throw IllegalStateException("Android VPN interface was not established")
      if (CleanWebVpnState.mihomoEnabled) {
        startMihomo(vpnInterface!!)
        CleanWebVpnState.markRunning("full_tunnel")
      } else {
        startPacketLoop(vpnInterface!!)
        CleanWebVpnState.markRunning("dns_only")
      }
    } catch (error: Exception) {
      CleanWebVpnState.markFailed(error.message ?: error.javaClass.simpleName)
      stopVpn(stopService = true, markStopped = false)
    }
  }

  private fun stopVpn(stopService: Boolean = true, markStopped: Boolean = true) {
    stopping = true
    packetLoopRunning = false
    packetThread?.interrupt()
    packetThread = null
    mihomoLogThread?.interrupt()
    mihomoLogThread = null
    mihomoProcess?.destroy()
    mihomoProcess = null
    vpnInterface?.close()
    vpnInterface = null
    if (markStopped) CleanWebVpnState.markStopped()
    stopForeground(STOP_FOREGROUND_REMOVE)
    if (stopService) stopSelf()
  }

  private fun startPacketLoop(descriptor: ParcelFileDescriptor) {
    packetLoopRunning = true
    packetThread = Thread({
      val input = FileInputStream(descriptor.fileDescriptor)
      val output = FileOutputStream(descriptor.fileDescriptor)
      val buffer = ByteArray(4096)
      while (packetLoopRunning) {
        val length = try {
          input.read(buffer)
        } catch (_: Exception) {
          break
        }
        if (length <= 0) continue
        val query = CleanWebTunDns.parseQuery(buffer, length) ?: continue
        val localResponse = CleanWebDnsEngine.handleDnsQuery(query.payload)
        val dnsResponse = try {
          localResponse ?: CleanWebTunDns.forwardDns(query, upstreamDnsServers) { socket: DatagramSocket -> protect(socket) }
        } catch (error: Exception) {
          CleanWebVpnState.recordUpstreamFailure(error.message ?: error.javaClass.simpleName)
          null
        }
        if (dnsResponse == null) {
          CleanWebVpnState.recordUpstreamFailure("All upstream DNS resolvers failed")
          continue
        }
        CleanWebVpnState.recordDnsQuery(localResponse != null && CleanWebTunDns.isNxDomain(dnsResponse))
        val responsePacket = CleanWebTunDns.buildResponse(query, dnsResponse)
        try {
          output.write(responsePacket)
        } catch (_: Exception) {
          break
        }
      }
      if (packetLoopRunning) {
        packetLoopRunning = false
        CleanWebVpnState.markFailed("Android DNS packet loop stopped unexpectedly")
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
      }
    }, "cleanweb-android-dns")
    packetThread?.start()
  }

  private fun startMihomo(descriptor: ParcelFileDescriptor) {
    val configPath = CleanWebVpnState.mihomoConfigPath
      ?: throw IllegalStateException("Android Mihomo config is not prepared")
    val sourceConfig = File(configPath)
    if (!sourceConfig.exists()) throw IllegalStateException("Android Mihomo config does not exist: $configPath")
    val executable = ensureMihomoExecutable()
    val runtimeDir = File(filesDir, "mihomo")
    runtimeDir.mkdirs()
    val activeConfig = File(runtimeDir, "active-config.yaml")
    activeConfig.writeText(sourceConfig.readText().replace("file-descriptor: 3", "file-descriptor: ${descriptor.fd}"))
    clearCloseOnExec(descriptor)
    val processBuilder = ProcessBuilder(executable.absolutePath, "-d", runtimeDir.absolutePath, "-f", activeConfig.absolutePath)
      .redirectErrorStream(true)
      .directory(runtimeDir)
    processBuilder.environment()["HOME"] = filesDir.absolutePath
    processBuilder.environment()["XDG_CONFIG_HOME"] = runtimeDir.absolutePath
    val process = processBuilder.start()
    mihomoProcess = process
    mihomoLogThread = Thread({
      var lastLine: String? = null
      process.inputStream.bufferedReader().useLines { lines ->
        lines.forEach { line ->
          lastLine = line.take(300)
          if (line.contains("error", ignoreCase = true) || line.contains("fail", ignoreCase = true)) {
            CleanWebVpnState.lastError = lastLine
          }
        }
      }
      val exitCode = process.waitFor()
      if (!stopping && mihomoProcess == process) {
        mihomoProcess = null
        CleanWebVpnState.markFailed("Android Mihomo exited with code $exitCode${lastLine?.let { ": $it" } ?: ""}")
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
      }
    }, "cleanweb-mihomo-log")
    mihomoLogThread?.start()
  }

  private fun ensureMihomoExecutable(): File {
    val abi = Build.SUPPORTED_ABIS.firstOrNull()
      ?: throw IllegalStateException("Android ABI is unavailable")
    val libraryName = when {
      abi == "arm64-v8a" -> "libmihomo.so"
      else -> throw IllegalStateException("当前 Android ABI 暂未打包 Mihomo 核心：$abi")
    }
    val executable = File(applicationInfo.nativeLibraryDir, libraryName)
    if (!executable.exists()) throw IllegalStateException("Android Mihomo 核心不存在：${executable.absolutePath}")
    return executable
  }

  private fun clearCloseOnExec(descriptor: ParcelFileDescriptor) {
    try {
      val flags = Os.fcntlInt(descriptor.fileDescriptor, OsConstants.F_GETFD, 0)
      Os.fcntlInt(descriptor.fileDescriptor, OsConstants.F_SETFD, flags and OsConstants.FD_CLOEXEC.inv())
    } catch (error: Exception) {
      throw IllegalStateException("Android VPN fd could not be inherited by Mihomo: ${error.message}")
    }
  }

  private fun captureUpstreamDnsServers(): List<InetAddress> {
    val manager = getSystemService(ConnectivityManager::class.java)
    val systemResolvers = manager.activeNetwork
      ?.let { manager.getLinkProperties(it) }
      ?.dnsServers
      .orEmpty()
      .filterNot { it.hostAddress == CLEANWEB_DNS_ADDRESS }
      .distinctBy { it.hostAddress }
    if (systemResolvers.isNotEmpty()) return systemResolvers
    return FALLBACK_DNS_ADDRESSES.map(InetAddress::getByName)
  }

  private fun buildNotification(contentText: String): Notification {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val manager = getSystemService(NotificationManager::class.java)
      val channel = NotificationChannel(
        NOTIFICATION_CHANNEL_ID,
        "CleanWeb VPN",
        NotificationManager.IMPORTANCE_LOW,
      )
      manager.createNotificationChannel(channel)
    }

    val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
    } else {
      @Suppress("DEPRECATION")
      Notification.Builder(this)
    }

    return builder
      .setSmallIcon(R.mipmap.ic_launcher)
      .setContentTitle("CleanWeb")
      .setContentText(contentText)
      .setOngoing(true)
      .setContentIntent(configureIntent())
      .build()
  }

  private fun configureIntent(): PendingIntent {
    val intent = packageManager.getLaunchIntentForPackage(packageName)
      ?: Intent(this, MainActivity::class.java)
    return PendingIntent.getActivity(
      this,
      0,
      intent,
      PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )
  }

  companion object {
    const val ACTION_START = "app.cleanweb.mobile.vpn.START"
    const val ACTION_STOP = "app.cleanweb.mobile.vpn.STOP"
    private const val CLEANWEB_DNS_ADDRESS = "10.255.0.1"
    private const val NOTIFICATION_CHANNEL_ID = "cleanweb_vpn"
    private const val NOTIFICATION_ID = 1001
    private val FALLBACK_DNS_ADDRESSES = listOf("1.1.1.1", "8.8.8.8")
  }
}
