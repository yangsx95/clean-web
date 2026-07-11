pub mod rules;
pub mod subscription_download;
pub mod storage;
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
            subscription_download::refresh_subscription,
            subscription_download::refresh_due_subscriptions,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CleanWeb");
}
