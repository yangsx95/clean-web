pub mod access_logs;
pub mod mihomo;
pub mod platform;
pub mod proxy_crypto;
pub mod rules;
pub mod storage;
pub mod subscription_download;
pub mod subscriptions;

use std::fs;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            fs::create_dir_all(&data_dir)?;
            app.manage(storage::AppState::open(data_dir.join("cleanweb.db"))?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            storage::get_bootstrap_state,
            storage::initialize_password,
            storage::unlock,
            storage::lock,
            storage::get_settings,
            storage::update_setting,
            storage::list_subscriptions,
            storage::create_subscription,
            storage::set_subscription_enabled,
            storage::delete_subscription,
            storage::get_recommended_sources,
            storage::list_parent_rules,
            storage::create_parent_rule,
            storage::set_parent_rule_enabled,
            storage::delete_parent_rule,
            subscription_download::refresh_subscription,
            subscription_download::refresh_due_subscriptions,
            mihomo::get_core_status,
            mihomo::start_protection,
            mihomo::stop_protection,
            mihomo::test_proxy_group,
            mihomo::get_proxies,
            mihomo::get_subscription_proxies,
            mihomo::select_proxy,
            mihomo::test_all_proxy_delays,
            mihomo::get_network_conflicts,
            mihomo::auto_start_protection,
            access_logs::sync_access_logs,
            access_logs::list_access_logs,
            access_logs::clear_access_logs,
            access_logs::export_access_logs_csv,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CleanWeb");
}
