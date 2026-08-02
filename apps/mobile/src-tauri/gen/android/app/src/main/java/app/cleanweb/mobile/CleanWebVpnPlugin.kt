package app.cleanweb.mobile

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin

@InvokeArg
class UpdatePolicyArgs {
  lateinit var policyJson: String
}

@TauriPlugin
class CleanWebVpnPlugin(private val activity: Activity) : Plugin(activity) {
  @Command
  fun prepareVpn(invoke: Invoke) {
    val prepareIntent = VpnService.prepare(activity)
    if (prepareIntent == null) {
      invoke.resolve(CleanWebVpnState.status(activity))
      return
    }
    startActivityForResult(invoke, prepareIntent, "vpnPrepared")
  }

  @ActivityCallback
  fun vpnPrepared(invoke: Invoke, result: ActivityResult) {
    if (result.resultCode == Activity.RESULT_OK && CleanWebVpnState.prepared(activity)) {
      invoke.resolve(CleanWebVpnState.status(activity))
    } else {
      CleanWebVpnState.stage = "permission_denied"
      CleanWebVpnState.lastError = "VPN permission was not granted"
      invoke.reject("VPN permission was not granted")
    }
  }

  @Command
  fun startVpn(invoke: Invoke) {
    if (!CleanWebVpnState.prepared(activity)) {
      CleanWebVpnState.stage = "permission_required"
      CleanWebVpnState.lastError = "VPN permission is required"
      invoke.reject("VPN permission is required")
      return
    }

    CleanWebVpnState.stage = "starting"
    CleanWebVpnState.running = true
    CleanWebVpnState.lastError = null
    val intent = Intent(activity, CleanWebVpnService::class.java).apply {
      action = CleanWebVpnService.ACTION_START
    }
    ContextCompat.startForegroundService(activity, intent)
    invoke.resolve(CleanWebVpnState.status(activity))
  }

  @Command
  fun stopVpn(invoke: Invoke) {
    val intent = Intent(activity, CleanWebVpnService::class.java).apply {
      action = CleanWebVpnService.ACTION_STOP
    }
    activity.startService(intent)
    CleanWebVpnState.running = false
    CleanWebVpnState.stage = "stopped"
    invoke.resolve(CleanWebVpnState.status(activity))
  }

  @Command
  fun vpnStatus(invoke: Invoke) {
    invoke.resolve(CleanWebVpnState.status(activity))
  }

  @Command
  fun updatePolicy(invoke: Invoke) {
    try {
      val args = invoke.parseArgs(UpdatePolicyArgs::class.java)
      CleanWebVpnState.updatePolicy(activity, args.policyJson)
      invoke.resolve(CleanWebVpnState.status(activity))
    } catch (error: Exception) {
      invoke.reject(error.message ?: error.javaClass.simpleName)
    }
  }
}
