pub mod access_logs;
pub mod builtin_rules;
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
const QUIT_MENU_ID: &str = "cleanweb-quit";
#[cfg(target_os = "macos")]
const TRAY_ID: &str = "cleanweb-tray";

#[derive(Default)]
struct AppLifecycle {
    confirmed_exit: AtomicBool,
    quit_requested: AtomicBool,
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn request_quit_confirmation(app: &tauri::AppHandle) {
    app.state::<AppLifecycle>()
        .quit_requested
        .store(true, Ordering::SeqCst);
    show_main_window(app);
    let _ = app.emit(QUIT_REQUESTED_EVENT, ());
}

fn hide_to_background(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

#[tauri::command]
fn hide_main_window(app: tauri::AppHandle) {
    hide_to_background(&app);
}

#[tauri::command]
fn confirmed_quit(app: tauri::AppHandle, lifecycle: tauri::State<'_, AppLifecycle>) {
    lifecycle.quit_requested.store(false, Ordering::SeqCst);
    lifecycle.confirmed_exit.store(true, Ordering::SeqCst);
    app.exit(0);
}

#[tauri::command]
fn take_pending_quit_request(lifecycle: tauri::State<'_, AppLifecycle>) -> bool {
    lifecycle.quit_requested.swap(false, Ordering::SeqCst)
}

#[cfg(target_os = "macos")]
fn build_macos_menu(app: &tauri::AppHandle) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};

    let menu = Menu::new(app)?;
    let app_menu = Submenu::new(app, "CleanWeb", true)?;
    let show = MenuItem::with_id(
        app,
        SHOW_WINDOW_MENU_ID,
        "显示主界面",
        true,
        Some("CmdOrCtrl+Shift+O"),
    )?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, QUIT_MENU_ID, "退出", true, Some("CmdOrCtrl+Q"))?;
    app_menu.append_items(&[&show, &separator, &quit])?;

    menu.append(&app_menu)?;
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
            if event.id() == SHOW_WINDOW_MENU_ID {
                show_main_window(app);
            } else if event.id() == QUIT_MENU_ID {
                request_quit_confirmation(app);
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
        .enable_macos_default_menu(false)
        .menu(|app| {
            #[cfg(target_os = "macos")]
            {
                build_macos_menu(app)
            }
            #[cfg(not(target_os = "macos"))]
            {
                tauri::menu::Menu::new(app)
            }
        })
        .on_menu_event(|app, event| {
            if event.id() == SHOW_WINDOW_MENU_ID {
                show_main_window(app);
            } else if event.id() == QUIT_MENU_ID {
                request_quit_confirmation(app);
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
            subscription_download::import_proxy_payload,
            subscription_download::refresh_subscription,
            subscription_download::refresh_due_subscriptions,
            mihomo::get_core_status,
            mihomo::start_protection,
            mihomo::stop_protection,
            mihomo::reload_protection,
            mihomo::test_proxy_group,
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
        ])
        .build(tauri::generate_context!())
        .expect("failed to build CleanWeb");

    app.run(|app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let lifecycle = app.state::<AppLifecycle>();
            if !lifecycle.confirmed_exit.swap(false, Ordering::SeqCst) {
                api.prevent_exit();
                request_quit_confirmation(app);
            }
        }
    });
}
