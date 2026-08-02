package app.cleanweb.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

class CleanWebVpnService : VpnService() {
  private var vpnInterface: ParcelFileDescriptor? = null

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
      startForeground(NOTIFICATION_ID, buildNotification())

      val builder = Builder()
        .setSession("CleanWeb")
        .setMtu(1500)
        .addAddress("10.255.0.2", 32)
        .addRoute("10.255.0.1", 32)
        .setConfigureIntent(configureIntent())

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        builder.setMetered(false)
      }

      vpnInterface = builder.establish() ?: throw IllegalStateException("Android VPN interface was not established")
      CleanWebVpnState.running = true
      CleanWebVpnState.stage = "running"
    } catch (error: Exception) {
      CleanWebVpnState.running = false
      CleanWebVpnState.stage = "failed"
      CleanWebVpnState.lastError = error.message ?: error.javaClass.simpleName
      stopSelf()
    }
  }

  private fun stopVpn() {
    vpnInterface?.close()
    vpnInterface = null
    CleanWebVpnState.running = false
    CleanWebVpnState.stage = "stopped"
    stopForeground(STOP_FOREGROUND_REMOVE)
    stopSelf()
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
    private const val NOTIFICATION_CHANNEL_ID = "cleanweb_vpn"
    private const val NOTIFICATION_ID = 1001
  }
}
