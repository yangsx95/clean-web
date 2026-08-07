pub mod access_logs;
pub mod browser_policy;
pub mod dns_filter;
pub mod mihomo;
pub mod platform;
pub mod proxy_crypto;
pub mod rules;
pub mod storage;
pub mod subscription_download;
pub mod subscriptions;

use std::{
    fs,
    sync::atomic::{AtomicBool, Ordering},
};
use tauri::{Emitter, Manager};

const QUIT_REQUESTED_EVENT: &str = "cleanweb-quit-requested";
const SHOW_WINDOW_MENU_ID: &str = "cleanweb-show-window";
const CLOSE_WINDOW_MENU_ID: &str = "cleanweb-close-window";
const QUIT_MENU_ID: &str = "cleanweb-quit";
#[cfg(target_os = "macos")]
const TRAY_ID: &str = "cleanweb-tray";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MenuAction {
    ShowMainWindow,
    HideMainWindow,
    RequestQuitConfirmation,
}

#[derive(Default)]
struct AppLifecycle {
    confirmed_exit: AtomicBool,
    quit_requested: AtomicBool,
    network_cleanup_started: AtomicBool,
}

fn menu_action_for_id(id: &str) -> Option<MenuAction> {
    match id {
        SHOW_WINDOW_MENU_ID => Some(MenuAction::ShowMainWindow),
        CLOSE_WINDOW_MENU_ID => Some(MenuAction::HideMainWindow),
        QUIT_MENU_ID => Some(MenuAction::RequestQuitConfirmation),
        _ => None,
    }
}

fn handle_menu_action(app: &tauri::AppHandle, action: MenuAction) {
    match action {
        MenuAction::ShowMainWindow => show_main_window(app),
        MenuAction::HideMainWindow => hide_to_background(app),
        MenuAction::RequestQuitConfirmation => request_quit_confirmation(app),
    }
}

#[cfg(target_os = "macos")]
fn set_macos_activation_policy(app: &tauri::AppHandle, policy: tauri::ActivationPolicy) {
    let _ = app.set_activation_policy(policy);
}

fn show_main_window(app: &tauri::AppHandle) {
    #[cfg(target_os = "macos")]
    set_macos_activation_policy(app, tauri::ActivationPolicy::Regular);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn request_quit_confirmation(app: &tauri::AppHandle) {
    app.state::<AppLifecycle>()
        .quit_requested
        .store(true, Ordering::SeqCst);
    show_main_window(app);
    let _ = app.emit_to("main", QUIT_REQUESTED_EVENT, ());
    let _ = app.emit(QUIT_REQUESTED_EVENT, ());
}

fn hide_to_background(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    #[cfg(target_os = "macos")]
    set_macos_activation_policy(app, tauri::ActivationPolicy::Accessory);
}

#[tauri::command]
fn hide_main_window(app: tauri::AppHandle) {
    hide_to_background(&app);
}

#[tauri::command]
fn confirmed_quit(
    password: String,
    app: tauri::AppHandle,
    lifecycle: tauri::State<'_, AppLifecycle>,
    state: tauri::State<'_, storage::AppState>,
) -> Result<(), String> {
    storage::verify_management_password(&password, &state)?;
    stop_network_runtime_once(&lifecycle, &state)?;
    lifecycle.quit_requested.store(false, Ordering::SeqCst);
    lifecycle.confirmed_exit.store(true, Ordering::SeqCst);
    app.exit(0);
    Ok(())
}

#[tauri::command]
fn take_pending_quit_request(lifecycle: tauri::State<'_, AppLifecycle>) -> bool {
    lifecycle.quit_requested.swap(false, Ordering::SeqCst)
}

fn stop_network_runtime_once(
    lifecycle: &AppLifecycle,
    state: &storage::AppState,
) -> Result<(), String> {
    if lifecycle
        .network_cleanup_started
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok(());
    }
    let result = mihomo::stop_child(state);
    if result.is_err() {
        lifecycle
            .network_cleanup_started
            .store(false, Ordering::SeqCst);
    }
    result
}

fn build_desktop_menu(app: &tauri::AppHandle) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};

    let menu = Menu::default(app)?;
    let control_menu = Submenu::new(app, "控制", true)?;
    let show = MenuItem::with_id(
        app,
        SHOW_WINDOW_MENU_ID,
        "显示主界面",
        true,
        Some("CmdOrCtrl+Shift+O"),
    )?;
    let close = MenuItem::with_id(app, CLOSE_WINDOW_MENU_ID, "隐藏到后台", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, QUIT_MENU_ID, "退出", true, None::<&str>)?;
    control_menu.append_items(&[&show, &close, &separator, &quit])?;
    menu.append(&control_menu)?;
    Ok(menu)
}

#[cfg(target_os = "macos")]
fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::{
        menu::{Menu, MenuItem, PredefinedMenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    };

    let menu = Menu::new(app)?;
    let show = MenuItem::with_id(app, SHOW_WINDOW_MENU_ID, "显示主界面", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, QUIT_MENU_ID, "退出", true, None::<&str>)?;
    menu.append_items(&[&show, &separator, &quit])?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("CleanWeb")
        .on_menu_event(|app, event| {
            if let Some(action) = menu_action_for_id(event.id().as_ref()) {
                handle_menu_action(app, action);
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .manage(AppLifecycle::default())
        .plugin(tauri_plugin_dialog::init())
        .enable_macos_default_menu(false)
        .menu(build_desktop_menu)
        .on_menu_event(|app, event| {
            if let Some(action) = menu_action_for_id(event.id().as_ref()) {
                handle_menu_action(app, action);
            }
        })
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            fs::create_dir_all(&data_dir)?;
            app.manage(storage::AppState::open(data_dir.join("cleanweb.db"))?);
            access_logs::start_access_log_collector(app.handle().clone());
            #[cfg(target_os = "macos")]
            {
                build_tray(app.handle())?;
                if let Ok(executable) = std::env::current_exe() {
                    platform::install_login_agent(&executable).map_err(std::io::Error::other)?;
                }
                if let Some(window) = app.get_webview_window("main") {
                    let close_window = window.clone();
                    window.on_window_event(move |event| {
                        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                            api.prevent_close();
                            hide_to_background(close_window.app_handle());
                        }
                    });
                    if std::env::args().any(|argument| argument == "--background") {
                        hide_to_background(app.handle());
                    }
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            storage::get_bootstrap_state,
            hide_main_window,
            confirmed_quit,
            take_pending_quit_request,
            storage::initialize_password,
            storage::verify_password,
            storage::unlock,
            storage::lock,
            storage::get_settings,
            storage::update_setting,
            storage::list_subscriptions,
            storage::create_subscription,
            storage::update_subscription,
            storage::set_subscription_enabled,
            storage::delete_subscription,
            storage::get_recommended_sources,
            storage::list_parent_rules,
            storage::create_parent_rule,
            storage::set_parent_rule_enabled,
            storage::delete_parent_rule,
            storage::diagnose_rule_match,
            subscription_download::import_proxy_payload,
            subscription_download::refresh_subscription,
            subscription_download::refresh_due_subscriptions,
            mihomo::get_core_status,
            mihomo::start_protection,
            mihomo::stop_protection,
            mihomo::reload_protection,
            mihomo::test_proxy_group,
            mihomo::test_proxy_connectivity,
            mihomo::get_proxies,
            mihomo::get_subscription_proxies,
            mihomo::select_proxy,
            mihomo::test_all_proxy_delays,
            mihomo::get_network_conflicts,
            mihomo::auto_start_protection,
            access_logs::sync_access_logs,
            access_logs::list_access_logs,
            access_logs::access_log_stats,
            access_logs::public_access_log_stats,
            access_logs::clear_access_logs,
            access_logs::export_access_logs_csv,
            access_logs::export_access_logs_csv_to_path,
            browser_policy::get_browser_policy_status,
            browser_policy::apply_browser_policies,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build CleanWeb");

    app.run(|app, event| match event {
        tauri::RunEvent::ExitRequested { api, .. } => {
            let lifecycle = app.state::<AppLifecycle>();
            if !lifecycle.confirmed_exit.swap(false, Ordering::SeqCst) {
                api.prevent_exit();
                request_quit_confirmation(app);
            } else {
                let state = app.state::<storage::AppState>();
                if let Err(reason) = stop_network_runtime_once(&lifecycle, &state) {
                    eprintln!("CleanWeb failed to stop network runtime during exit: {reason}");
                }
            }
        }
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen {
            has_visible_windows: false,
            ..
        } => {
            show_main_window(app);
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_menu_item_hides_main_window() {
        assert_eq!(
            menu_action_for_id(CLOSE_WINDOW_MENU_ID),
            Some(MenuAction::HideMainWindow)
        );
    }

    #[test]
    fn quit_menu_requests_password_confirmation() {
        assert_eq!(
            menu_action_for_id(QUIT_MENU_ID),
            Some(MenuAction::RequestQuitConfirmation)
        );
    }
}
