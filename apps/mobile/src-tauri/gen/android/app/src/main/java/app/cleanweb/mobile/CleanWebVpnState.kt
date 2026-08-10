package app.cleanweb.mobile

import android.content.Context
import android.net.VpnService
import app.tauri.plugin.JSObject
import org.json.JSONObject

object CleanWebVpnState {
  private const val PREFS = "cleanweb_vpn"
  private const val POLICY_JSON = "policy_json"
  private const val LAST_POLICY_UPDATED_AT = "last_policy_updated_at"

  @Volatile
  var running: Boolean = false

  @Volatile
  var stage: String = "stopped"

  @Volatile
  var lastError: String? = null

  @Volatile
  var dataPlaneReady: Boolean = false

  @Volatile
  var lastPolicyUpdatedAt: Long = 0

  @Volatile
  var lastStartedAt: Long = 0

  @Volatile
  var lastDnsActivityAt: Long = 0

  @Volatile
  var dnsQueryCount: Long = 0

  @Volatile
  var blockedDnsQueryCount: Long = 0

  @Volatile
  var upstreamFailureCount: Long = 0

  @Volatile
  var mihomoEnabled: Boolean = false

  @Volatile
  var mihomoConfigPath: String? = null

  @Volatile
  var dataPlaneMode: String = "dns_only"

  fun prepared(context: Context): Boolean = VpnService.prepare(context) == null

  fun updatePolicy(context: Context, policyJson: String) {
    val error = CleanWebDnsEngine.updatePolicy(policyJson)
    if (error != null) {
      stage = "policy_failed"
      lastError = error
      throw IllegalArgumentException(error)
    }
    val updatedAt = System.currentTimeMillis()
    val saved = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
      .putString(POLICY_JSON, policyJson)
      .putLong(LAST_POLICY_UPDATED_AT, updatedAt)
      .commit()
    if (!saved) throw IllegalStateException("Android policy could not be persisted")
    lastPolicyUpdatedAt = updatedAt
    updateRuntimePolicyFields(policyJson)
    lastError = null
  }

  fun markStarting() {
    running = false
    dataPlaneReady = false
    stage = "starting"
    lastError = null
  }

  fun markRunning(mode: String = dataPlaneMode) {
    running = true
    dataPlaneReady = true
    dataPlaneMode = mode
    stage = "running"
    lastStartedAt = System.currentTimeMillis()
    lastError = null
  }

  fun markStopped() {
    running = false
    dataPlaneReady = false
    stage = "stopped"
  }

  fun markFailed(error: String) {
    running = false
    dataPlaneReady = false
    stage = "failed"
    lastError = error
  }

  fun recordDnsQuery(blocked: Boolean) {
    dnsQueryCount += 1
    if (blocked) blockedDnsQueryCount += 1
    lastDnsActivityAt = System.currentTimeMillis()
  }

  fun recordUpstreamFailure(error: String) {
    upstreamFailureCount += 1
    lastError = error
  }

  fun status(context: Context): JSObject {
    return JSObject().apply {
      put("supported", true)
      put("prepared", prepared(context))
      put("running", running)
      put("stage", stage)
      put("dataPlaneReady", dataPlaneReady)
      put("dataPlaneMode", dataPlaneMode)
      put("lastError", lastError)
      put("lastPolicyUpdatedAt", lastPolicyUpdatedAt.takeIf { it > 0 })
      put("lastStartedAt", lastStartedAt.takeIf { it > 0 })
      put("lastDnsActivityAt", lastDnsActivityAt.takeIf { it > 0 })
      put("dnsQueryCount", dnsQueryCount)
      put("blockedDnsQueryCount", blockedDnsQueryCount)
      put("upstreamFailureCount", upstreamFailureCount)
    }
  }

  fun loadPolicy(context: Context) {
    val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val policyJson = preferences.getString(POLICY_JSON, "{}") ?: "{}"
    lastPolicyUpdatedAt = preferences.getLong(LAST_POLICY_UPDATED_AT, 0)
    updateRuntimePolicyFields(policyJson)
    val error = CleanWebDnsEngine.updatePolicy(policyJson)
    if (error != null) {
      stage = "policy_failed"
      lastError = error
      throw IllegalArgumentException(error)
    }
  }

  private fun updateRuntimePolicyFields(policyJson: String) {
    try {
      val json = JSONObject(policyJson)
      mihomoEnabled = json.optBoolean("mihomoEnabled", false)
      mihomoConfigPath = json.optString("mihomoConfigPath", "").takeIf { it.isNotBlank() }
      dataPlaneMode = if (mihomoEnabled) "full_tunnel" else "dns_only"
    } catch (_: Exception) {
      mihomoEnabled = false
      mihomoConfigPath = null
      dataPlaneMode = "dns_only"
    }
  }
}
