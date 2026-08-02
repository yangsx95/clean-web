package app.cleanweb.mobile

import android.content.Context
import android.net.VpnService
import app.tauri.plugin.JSObject

object CleanWebVpnState {
  private const val PREFS = "cleanweb_vpn"
  private const val POLICY_JSON = "policy_json"

  @Volatile
  var running: Boolean = false

  @Volatile
  var stage: String = "stopped"

  @Volatile
  var lastError: String? = null

  fun prepared(context: Context): Boolean = VpnService.prepare(context) == null

  fun updatePolicy(context: Context, policyJson: String) {
    context
      .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
      .edit()
      .putString(POLICY_JSON, policyJson)
      .apply()
  }

  fun status(context: Context): JSObject {
    return JSObject().apply {
      put("supported", true)
      put("prepared", prepared(context))
      put("running", running)
      put("stage", stage)
      put("dataPlaneReady", false)
      put("lastError", lastError)
    }
  }
}
