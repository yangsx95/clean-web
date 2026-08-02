use serde::{Deserialize, Serialize};
use tauri::plugin::TauriPlugin;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileVpnStatus {
    pub supported: bool,
    pub prepared: bool,
    pub running: bool,
    pub stage: String,
    pub data_plane_ready: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobilePolicyPayload {
    pub policy_json: String,
}

#[cfg(target_os = "android")]
pub fn init() -> TauriPlugin<tauri::Wry> {
    use tauri::{plugin::Builder, Manager};

    Builder::new("cleanwebVpn")
        .setup(|app, api| {
            let handle = api.register_android_plugin("app.cleanweb.mobile", "CleanWebVpnPlugin")?;
            app.manage(AndroidVpnPlugin(handle));
            Ok(())
        })
        .build()
}

#[cfg(not(target_os = "android"))]
pub fn init() -> TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("cleanwebVpn").build()
}

#[cfg(target_os = "android")]
pub(crate) struct AndroidVpnPlugin(tauri::plugin::PluginHandle<tauri::Wry>);

#[cfg(target_os = "android")]
fn plugin_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_prepare_vpn(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
) -> Result<MobileVpnStatus, String> {
    plugin
        .0
        .run_mobile_plugin_async("prepareVpn", serde_json::json!({}))
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_prepare_vpn() -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_start_vpn(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
) -> Result<MobileVpnStatus, String> {
    plugin
        .0
        .run_mobile_plugin_async("startVpn", serde_json::json!({}))
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_start_vpn() -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_stop_vpn(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
) -> Result<MobileVpnStatus, String> {
    plugin
        .0
        .run_mobile_plugin_async("stopVpn", serde_json::json!({}))
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_stop_vpn() -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_vpn_status(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
) -> Result<MobileVpnStatus, String> {
    plugin
        .0
        .run_mobile_plugin_async("vpnStatus", serde_json::json!({}))
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_vpn_status() -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(target_os = "android")]
#[tauri::command]
pub async fn mobile_update_policy(
    plugin: tauri::State<'_, AndroidVpnPlugin>,
    payload: MobilePolicyPayload,
) -> Result<MobileVpnStatus, String> {
    plugin
        .0
        .run_mobile_plugin_async("updatePolicy", payload)
        .await
        .map_err(plugin_error)
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
pub async fn mobile_update_policy(
    _payload: MobilePolicyPayload,
) -> Result<MobileVpnStatus, String> {
    Ok(unsupported_status())
}

#[cfg(not(target_os = "android"))]
fn unsupported_status() -> MobileVpnStatus {
    MobileVpnStatus {
        supported: false,
        prepared: false,
        running: false,
        stage: "unsupported".into(),
        data_plane_ready: false,
        last_error: Some("Android VPN is only available in the Android mobile app".into()),
    }
}
