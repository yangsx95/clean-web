package app.cleanweb.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket

class CleanWebVpnService : VpnService() {
  private var vpnInterface: ParcelFileDescriptor? = null
  @Volatile
  private var packetLoopRunning = false
  private var packetThread: Thread? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_STOP -> stopVpn()
      else -> startVpn()
    }
    return START_STICKY
  }

  override fun onDestroy() {
    stopVpn()
    super.onDestroy()
  }

  private fun startVpn() {
    if (vpnInterface != null) {
      CleanWebVpnState.running = true
      CleanWebVpnState.stage = "running"
      return
    }

    try {
      CleanWebVpnState.stage = "starting"
      CleanWebVpnState.lastError = null
      CleanWebVpnState.loadPolicy(this)
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
      CleanWebVpnState.running = true
      CleanWebVpnState.stage = "running"
      CleanWebVpnState.dataPlaneReady = true
    } catch (error: Exception) {
      CleanWebVpnState.running = false
      CleanWebVpnState.dataPlaneReady = false
      CleanWebVpnState.stage = "failed"
      CleanWebVpnState.lastError = error.message ?: error.javaClass.simpleName
      stopSelf()
    }
  }

  private fun stopVpn() {
    packetLoopRunning = false
    packetThread?.interrupt()
    packetThread = null
    vpnInterface?.close()
    vpnInterface = null
    CleanWebVpnState.running = false
    CleanWebVpnState.dataPlaneReady = false
    CleanWebVpnState.stage = "stopped"
    stopForeground(STOP_FOREGROUND_REMOVE)
    stopSelf()
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
        val dnsResponse = try {
          CleanWebDnsEngine.handleDnsQuery(query.payload)
            ?: CleanWebTunDns.forwardDns(query) { socket: DatagramSocket -> protect(socket) }
        } catch (error: Exception) {
          CleanWebVpnState.lastError = error.message ?: error.javaClass.simpleName
          null
        } ?: continue
        val responsePacket = CleanWebTunDns.buildResponse(query, dnsResponse)
        try {
          output.write(responsePacket)
        } catch (_: Exception) {
          break
        }
      }
    }, "cleanweb-android-dns")
    packetThread?.start()
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
      .setContentText("VPN protection shell is running")
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
  }
}
