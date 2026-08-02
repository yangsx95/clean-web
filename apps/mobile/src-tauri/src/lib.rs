mod mobile_vpn;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(mobile_vpn::init())
        .invoke_handler(tauri::generate_handler![
            mobile_vpn::mobile_prepare_vpn,
            mobile_vpn::mobile_start_vpn,
            mobile_vpn::mobile_stop_vpn,
            mobile_vpn::mobile_vpn_status,
            mobile_vpn::mobile_update_policy
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CleanWeb mobile app");
}
