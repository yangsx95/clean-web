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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.InetAddress

class CleanWebVpnService : VpnService() {
  private var vpnInterface: ParcelFileDescriptor? = null
  @Volatile
  private var packetLoopRunning = false
  private var packetThread: Thread? = null
  private var upstreamDnsServers: List<InetAddress> = emptyList()

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_STOP -> stopVpn()
      else -> startVpn()
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
      CleanWebVpnState.markStarting()
      CleanWebVpnState.loadPolicy(this)
      upstreamDnsServers = captureUpstreamDnsServers()
      startForeground(NOTIFICATION_ID, buildNotification())

      val builder = Builder()
        .setSession("CleanWeb")
        .setMtu(1500)
        .addAddress("10.255.0.2", 32)
        .addDnsServer(CLEANWEB_DNS_ADDRESS)
        .addRoute("10.255.0.1", 32)
        .setConfigureIntent(configureIntent())

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        builder.setMetered(false)
      }

      vpnInterface = builder.establish() ?: throw IllegalStateException("Android VPN interface was not established")
      startPacketLoop(vpnInterface!!)
      CleanWebVpnState.markRunning()
    } catch (error: Exception) {
      CleanWebVpnState.markFailed(error.message ?: error.javaClass.simpleName)
      stopSelf()
    }
  }

  private fun stopVpn(stopService: Boolean = true) {
    packetLoopRunning = false
    packetThread?.interrupt()
    packetThread = null
    vpnInterface?.close()
    vpnInterface = null
    CleanWebVpnState.markStopped()
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

  private fun buildNotification(): Notification {
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
      .setContentText("DNS filtering protection is running")
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
