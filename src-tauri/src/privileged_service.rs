//! Narrow IPC boundary for the macOS privileged networking service.
//!
//! The UI may ask the service to start or stop CleanWeb's fixed Mihomo
//! process. It cannot execute arbitrary commands or choose arbitrary install
//! destinations.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, TcpStream, ToSocketAddrs},
    os::unix::{fs::PermissionsExt, net::UnixListener, net::UnixStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

pub const PROTOCOL_VERSION: u32 = 11;
pub const SERVICE_LABEL: &str = "app.cleanweb.privileged-service";
pub const SOCKET_PATH: &str = "/var/run/cleanweb/service.sock";
const SYSTEM_RUNTIME_DIR: &str = "/Library/Application Support/CleanWeb";
const DNS_BACKUP_FILE: &str = "/Library/Application Support/CleanWeb/dns-backup.json";
const DESIRED_RUNNING_FILE: &str = "/Library/Application Support/CleanWeb/desired-running";
const ROUTE_STATE_FILE: &str = "/Library/Application Support/CleanWeb/route-interface";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_CRASH_RESTARTS: u32 = 3;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum ServiceRequest {
    Ping,
    Start {
        binary: String,
        config: String,
    },
    StartStack {
        binary: String,
        config: String,
        xray_binary: String,
        xray_config: String,
    },
    Stop {
        pid: Option<u32>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct ServiceResponse {
    ok: bool,
    version: u32,
    pid: Option<u32>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DnsBackup {
    service: String,
    servers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RouteState {
    tun_name: String,
    bypasses: Vec<BypassRoute>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BypassRoute {
    destination: IpAddr,
    gateway: String,
    interface: String,
}

#[derive(Debug)]
struct DefaultRoute {
    gateway: String,
    interface: String,
}

impl ServiceResponse {
    fn success(pid: Option<u32>) -> Self {
        Self {
            ok: true,
            version: PROTOCOL_VERSION,
            pid,
            error: None,
        }
    }

    fn failure(error: impl ToString) -> Self {
        Self {
            ok: false,
            version: PROTOCOL_VERSION,
            pid: None,
            error: Some(error.to_string()),
        }
    }
}

pub fn run() -> Result<(), String> {
    if !saved_core_running() {
        if Path::new(DESIRED_RUNNING_FILE).is_file() {
            if let Err(value) = recover_core_after_service_restart() {
                eprintln!("CleanWeb failed to recover Mihomo: {value}");
                let _ = fs::remove_file(DESIRED_RUNNING_FILE);
                let _ = restore_dns();
            }
        } else {
            let _ = remove_cleanweb_routes();
            let _ = restore_dns();
        }
    } else {
        let xray_config = Path::new(SYSTEM_RUNTIME_DIR).join("xray.json");
        let mihomo_config = Path::new(SYSTEM_RUNTIME_DIR).join("config.yaml");
        if let Ok(name) = xray_tun_name(&xray_config) {
            let _ = configure_cleanweb_routes(&name, &mihomo_config);
        }
    }
    let socket = Path::new(SOCKET_PATH);
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent).map_err(error)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).map_err(error)?;
    }
    let _ = fs::remove_file(socket);
    let listener = UnixListener::bind(socket).map_err(error)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660)).map_err(error)?;
    // macOS' admin group is GID 80. Only root and administrators may control
    // protection; standard child accounts cannot connect to this socket.
    let path = std::ffi::CString::new(SOCKET_PATH).map_err(error)?;
    if unsafe { libc::chown(path.as_ptr(), 0, 80) } != 0 {
        return Err(format!(
            "无法限制特权服务套接字权限：{}",
            std::io::Error::last_os_error()
        ));
    }

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let response = handle_stream(&mut stream);
                let mut encoded = serde_json::to_vec(&response).map_err(error)?;
                encoded.push(b'\n');
                let _ = stream.write_all(&encoded);
            }
            Err(value) => eprintln!("CleanWeb privileged service IPC error: {value}"),
        }
    }
    Ok(())
}

fn handle_stream(stream: &mut UnixStream) -> ServiceResponse {
    let mut request = String::new();
    let read = BufReader::new(stream)
        .take(MAX_REQUEST_BYTES)
        .read_line(&mut request);
    if let Err(value) = read {
        return ServiceResponse::failure(value);
    }
    let request: ServiceRequest = match serde_json::from_str(&request) {
        Ok(value) => value,
        Err(value) => return ServiceResponse::failure(format!("IPC 请求无效：{value}")),
    };
    match request {
        ServiceRequest::Ping => ServiceResponse::success(None),
        ServiceRequest::Start { binary, config } => match start_core(&binary, &config) {
            Ok(pid) => ServiceResponse::success(Some(pid)),
            Err(value) => ServiceResponse::failure(value),
        },
        ServiceRequest::StartStack {
            binary,
            config,
            xray_binary,
            xray_config,
        } => match start_stack_core(&binary, &config, &xray_binary, &xray_config) {
            Ok(pid) => ServiceResponse::success(Some(pid)),
            Err(value) => ServiceResponse::failure(value),
        },
        ServiceRequest::Stop { pid } => match stop_core(pid) {
            Ok(()) => ServiceResponse::success(None),
            Err(value) => ServiceResponse::failure(value),
        },
    }
}

fn start_stack_core(
    binary: &str,
    config: &str,
    xray_binary: &str,
    xray_config: &str,
) -> Result<u32, String> {
    let source_binary = validate_source_in(binary, "mihomo", "mihomo")?;
    let source_config = validate_source_in(config, "config.yaml", "mihomo")?;
    let source_xray = validate_source_in(xray_binary, "xray", "xray")?;
    let source_xray_config = validate_source_in(xray_config, "config.json", "xray")?;
    stop_core(None)?;

    let runtime = PathBuf::from(SYSTEM_RUNTIME_DIR);
    fs::create_dir_all(&runtime).map_err(error)?;
    let installed_binary = runtime.join("mihomo");
    let installed_config = runtime.join("config.yaml");
    let installed_xray = runtime.join("xray");
    let installed_xray_config = runtime.join("xray.json");
    copy_runtime_file(&source_binary, &installed_binary, 0o700)?;
    copy_runtime_file(&source_config, &installed_config, 0o600)?;
    copy_runtime_file(&source_xray, &installed_xray, 0o700)?;
    copy_runtime_file(&source_xray_config, &installed_xray_config, 0o600)?;

    let mut mihomo = spawn_installed_core(
        &installed_binary,
        &installed_config,
        &runtime.join("mihomo.log"),
        true,
    )?;
    if let Err(value) = wait_for_transport() {
        let _ = mihomo.kill();
        let _ = mihomo.wait();
        return Err(value);
    }
    let mut xray = match spawn_xray(
        &installed_xray,
        &installed_xray_config,
        &runtime.join("xray.log"),
        true,
    ) {
        Ok(child) => child,
        Err(value) => {
            let _ = mihomo.kill();
            let _ = mihomo.wait();
            return Err(value);
        }
    };
    let tun_name = match xray_tun_name(&installed_xray_config) {
        Ok(value) => value,
        Err(value) => {
            let _ = xray.kill();
            let _ = xray.wait();
            let _ = mihomo.kill();
            let _ = mihomo.wait();
            return Err(value);
        }
    };
    if let Err(value) = wait_for_tun_and_configure_routes(&tun_name, &installed_config) {
        let _ = xray.kill();
        let _ = xray.wait();
        let _ = mihomo.kill();
        let _ = mihomo.wait();
        let _ = remove_cleanweb_routes();
        let _ = restore_dns();
        return Err(value);
    }
    let mihomo_pid = mihomo.id();
    fs::write(runtime.join("mihomo.pid"), mihomo_pid.to_string()).map_err(error)?;
    fs::write(runtime.join("xray.pid"), xray.id().to_string()).map_err(error)?;
    fs::write(DESIRED_RUNNING_FILE, b"1").map_err(error)?;
    fs::set_permissions(DESIRED_RUNNING_FILE, fs::Permissions::from_mode(0o600)).map_err(error)?;
    supervise_stack(
        mihomo,
        xray,
        installed_binary,
        installed_config,
        installed_xray,
        installed_xray_config,
    );
    Ok(mihomo_pid)
}

fn copy_runtime_file(source: &Path, target: &Path, mode: u32) -> Result<(), String> {
    fs::copy(source, target).map_err(error)?;
    fs::set_permissions(target, fs::Permissions::from_mode(mode)).map_err(error)
}

fn wait_for_transport() -> Result<(), String> {
    for _ in 0..50 {
        if TcpStream::connect_timeout(
            &"127.0.0.1:17890".parse().map_err(error)?,
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("Mihomo 传输后端未在 5 秒内就绪".into())
}

fn xray_tun_name(config: &Path) -> Result<String, String> {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(config).map_err(error)?).map_err(error)?;
    let name = value
        .get("inbounds")
        .and_then(serde_json::Value::as_array)
        .and_then(|inbounds| {
            inbounds.iter().find(|inbound| {
                inbound.get("tag").and_then(serde_json::Value::as_str) == Some("cleanweb-tun")
            })
        })
        .and_then(|inbound| inbound.pointer("/settings/name"))
        .and_then(serde_json::Value::as_str)
        .ok_or("Xray 配置缺少 TUN 名称")?;
    let suffix = name.strip_prefix("utun").ok_or("Xray TUN 名称无效")?;
    if suffix.is_empty() || !suffix.bytes().all(|value| value.is_ascii_digit()) {
        return Err("Xray TUN 名称无效".into());
    }
    Ok(name.to_owned())
}

fn wait_for_tun_and_configure_routes(tun_name: &str, mihomo_config: &Path) -> Result<(), String> {
    for _ in 0..50 {
        if Command::new("/sbin/ifconfig")
            .arg(tun_name)
            .status()
            .is_ok_and(|status| status.success())
        {
            configure_cleanweb_routes(tun_name, mihomo_config)?;
            configure_xray_access_log_permissions()?;
            configure_cleanweb_dns()?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!("等待 Clean Web TUN {tun_name} 就绪超时"))
}

fn configure_cleanweb_routes(tun_name: &str, mihomo_config: &Path) -> Result<(), String> {
    remove_cleanweb_routes()?;
    let bypasses = install_proxy_bypass_routes(mihomo_config)?;
    let ipv4_routes = ["0.0.0.0/1", "128.0.0.0/1"];
    for destination in ipv4_routes {
        let output = Command::new("/sbin/route")
            .args(["-n", "add", "-net", destination, "-interface", tun_name])
            .output()
            .map_err(error)?;
        if !output.status.success() {
            let _ = remove_routes_for_interface(tun_name);
            remove_bypass_routes(&bypasses);
            return Err(format!(
                "无法把 {destination} 路由到 {tun_name}：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    // Xray's Darwin TUN accepts IPv6 packets, but some IPv4-only networks do
    // not have an IPv6 route to replace. Treat these routes as best effort.
    for destination in ["::/1", "8000::/1"] {
        let _ = Command::new("/sbin/route")
            .args([
                "-n",
                "add",
                "-inet6",
                "-net",
                destination,
                "-interface",
                tun_name,
            ])
            .output();
    }
    for bypass in &bypasses {
        if route_interface_for(bypass.destination).as_deref() != Some(&bypass.interface) {
            let _ = remove_routes_for_interface(tun_name);
            remove_bypass_routes(&bypasses);
            return Err(format!(
                "代理节点 {} 未通过物理网卡 {}，未启动保护以避免出站路由循环",
                bypass.destination, bypass.interface
            ));
        }
    }
    let state = RouteState {
        tun_name: tun_name.to_owned(),
        bypasses,
    };
    if let Err(value) = serde_json::to_vec(&state)
        .map_err(std::io::Error::other)
        .and_then(|value| fs::write(ROUTE_STATE_FILE, value))
        .and_then(|()| fs::set_permissions(ROUTE_STATE_FILE, fs::Permissions::from_mode(0o600)))
    {
        let _ = remove_routes_for_interface(tun_name);
        remove_bypass_routes(&state.bypasses);
        return Err(error(value));
    }
    Ok(())
}

fn install_proxy_bypass_routes(mihomo_config: &Path) -> Result<Vec<BypassRoute>, String> {
    let hosts = proxy_server_hosts(mihomo_config)?;
    if hosts.is_empty() {
        return Ok(Vec::new());
    }
    let addresses = resolve_proxy_servers(&hosts);
    if addresses.is_empty() {
        return Err("无法解析任何代理节点地址，未启动保护以避免代理出站路由循环".into());
    }
    let ipv4_default = default_route(false);
    let ipv6_default = default_route(true);
    let mut installed = Vec::new();
    for destination in addresses {
        let route = if destination.is_ipv4() {
            ipv4_default.as_ref()
        } else {
            ipv6_default.as_ref()
        };
        let Some(route) = route else {
            continue;
        };
        let destination_text = destination.to_string();
        let mut args = vec!["-n", "add"];
        if destination.is_ipv6() {
            args.push("-inet6");
        }
        args.extend(["-host", &destination_text, &route.gateway]);
        let output = Command::new("/sbin/route")
            .args(&args)
            .output()
            .map_err(error)?;
        if !output.status.success()
            && !String::from_utf8_lossy(&output.stderr).contains("File exists")
        {
            remove_bypass_routes(&installed);
            return Err(format!(
                "无法为代理节点 {destination} 保留物理网卡路由：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        if !output.status.success() {
            // The route predates CleanWeb and must not be deleted on stop.
            continue;
        }
        installed.push(BypassRoute {
            destination,
            gateway: route.gateway.clone(),
            interface: route.interface.clone(),
        });
    }
    Ok(installed)
}

fn proxy_server_hosts(config: &Path) -> Result<BTreeSet<String>, String> {
    let value: serde_yaml::Value = serde_yaml::from_slice(&fs::read(config).map_err(error)?)
        .map_err(|value| format!("Mihomo 配置无法读取代理端点：{value}"))?;
    let uses_proxy = value
        .get("rules")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(serde_yaml::Value::as_str)
        .any(|rule| rule == "MATCH,CleanWeb");
    if !uses_proxy {
        return Ok(BTreeSet::new());
    }
    Ok(value
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|proxy| proxy.get("server").and_then(serde_yaml::Value::as_str))
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect())
}

fn resolve_proxy_servers(hosts: &BTreeSet<String>) -> BTreeSet<IpAddr> {
    hosts
        .iter()
        .flat_map(|host| {
            host.parse::<IpAddr>()
                .map(|address| vec![address])
                .unwrap_or_else(|_| {
                    (host.as_str(), 443)
                        .to_socket_addrs()
                        .map(|values| values.map(|value| value.ip()).collect())
                        .unwrap_or_default()
                })
        })
        .collect()
}

fn default_route(ipv6: bool) -> Option<DefaultRoute> {
    let mut command = Command::new("/sbin/route");
    command.args(["-n", "get"]);
    if ipv6 {
        command.arg("-inet6");
    }
    let output = command.arg("default").output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_default_route(&String::from_utf8(output.stdout).ok()?)
}

fn parse_default_route(output: &str) -> Option<DefaultRoute> {
    let field = |name: &str| {
        output.lines().find_map(|line| {
            line.trim()
                .strip_prefix(name)
                .map(str::trim)
                .map(str::to_owned)
        })
    };
    Some(DefaultRoute {
        gateway: field("gateway:")?,
        interface: field("interface:")?,
    })
}

fn route_interface_for(destination: IpAddr) -> Option<String> {
    let mut command = Command::new("/sbin/route");
    command.args(["-n", "get"]);
    if destination.is_ipv6() {
        command.arg("-inet6");
    }
    let output = command.arg(destination.to_string()).output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_default_route(&String::from_utf8(output.stdout).ok()?).map(|route| route.interface)
}

fn configure_xray_access_log_permissions() -> Result<(), String> {
    let path = Path::new(SYSTEM_RUNTIME_DIR).join("xray-access.log");
    for _ in 0..20 {
        if path.is_file() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).map_err(error)?;
            let encoded =
                std::ffi::CString::new(path.to_string_lossy().as_bytes()).map_err(error)?;
            if unsafe { libc::chown(encoded.as_ptr(), 0, 80) } != 0 {
                return Err(format!(
                    "无法限制 Xray 访问日志权限：{}",
                    std::io::Error::last_os_error()
                ));
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("Xray 未创建访问日志文件".into())
}

fn remove_cleanweb_routes() -> Result<(), String> {
    let path = Path::new(ROUTE_STATE_FILE);
    let Ok(contents) = fs::read(path) else {
        return Ok(());
    };
    if let Ok(state) = serde_json::from_slice::<RouteState>(&contents) {
        remove_routes_for_interface(&state.tun_name)?;
        remove_bypass_routes(&state.bypasses);
    } else {
        // Protocol 9 stored only the interface name. Keep upgrade cleanup
        // compatible so an older route cannot survive helper replacement.
        remove_routes_for_interface(String::from_utf8_lossy(&contents).trim())?;
    }
    let _ = fs::remove_file(path);
    Ok(())
}

fn remove_bypass_routes(routes: &[BypassRoute]) {
    for route in routes {
        let destination = route.destination.to_string();
        let mut args = vec!["-n", "delete"];
        if route.destination.is_ipv6() {
            args.push("-inet6");
        }
        args.extend(["-host", &destination, &route.gateway]);
        let _ = Command::new("/sbin/route").args(&args).output();
    }
}

fn remove_routes_for_interface(tun_name: &str) -> Result<(), String> {
    if !tun_name.starts_with("utun") {
        return Err("拒绝清理无效的 TUN 路由".into());
    }
    for destination in ["0.0.0.0/1", "128.0.0.0/1"] {
        let _ = Command::new("/sbin/route")
            .args(["-n", "delete", "-net", destination, "-interface", tun_name])
            .output();
    }
    for destination in ["::/1", "8000::/1"] {
        let _ = Command::new("/sbin/route")
            .args([
                "-n",
                "delete",
                "-inet6",
                "-net",
                destination,
                "-interface",
                tun_name,
            ])
            .output();
    }
    Ok(())
}

fn start_core(binary: &str, config: &str) -> Result<u32, String> {
    let source_binary = validate_source(binary, "mihomo")?;
    let source_config = validate_source(config, "config.yaml")?;
    stop_core(None)?;

    let runtime = PathBuf::from(SYSTEM_RUNTIME_DIR);
    fs::create_dir_all(&runtime).map_err(error)?;
    let installed_binary = runtime.join("mihomo");
    let installed_config = runtime.join("config.yaml");
    let log_path = runtime.join("mihomo.log");
    fs::copy(&source_binary, &installed_binary).map_err(error)?;
    fs::set_permissions(&installed_binary, fs::Permissions::from_mode(0o700)).map_err(error)?;
    fs::copy(&source_config, &installed_config).map_err(error)?;
    fs::set_permissions(&installed_config, fs::Permissions::from_mode(0o600)).map_err(error)?;
    let mut child = spawn_installed_core(&installed_binary, &installed_config, &log_path, true)?;
    let pid = child.id();
    fs::write(runtime.join("mihomo.pid"), pid.to_string()).map_err(error)?;
    fs::write(DESIRED_RUNNING_FILE, b"1").map_err(error)?;
    fs::set_permissions(DESIRED_RUNNING_FILE, fs::Permissions::from_mode(0o600)).map_err(error)?;
    if let Err(value) = configure_cleanweb_dns() {
        let _ = fs::remove_file(DESIRED_RUNNING_FILE);
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(runtime.join("mihomo.pid"));
        let _ = restore_dns();
        return Err(value);
    }
    supervise_core(child, installed_binary, installed_config, log_path);
    Ok(pid)
}

fn recover_core_after_service_restart() -> Result<(), String> {
    let runtime = PathBuf::from(SYSTEM_RUNTIME_DIR);
    let binary = runtime.join("mihomo");
    let config = runtime.join("config.yaml");
    let log = runtime.join("mihomo.log");
    if !binary.is_file() || !config.is_file() {
        return Err("缺少可恢复的 Mihomo 二进制或配置".into());
    }
    let xray_binary = runtime.join("xray");
    let xray_config = runtime.join("xray.json");
    if xray_binary.is_file() && xray_config.is_file() {
        let mut mihomo = spawn_installed_core(&binary, &config, &log, false)?;
        wait_for_transport().inspect_err(|_| {
            let _ = mihomo.kill();
            let _ = mihomo.wait();
        })?;
        let mut xray = spawn_xray(&xray_binary, &xray_config, &runtime.join("xray.log"), false)?;
        let tun_name = xray_tun_name(&xray_config)?;
        if let Err(value) = wait_for_tun_and_configure_routes(&tun_name, &config) {
            let _ = xray.kill();
            let _ = xray.wait();
            let _ = mihomo.kill();
            let _ = mihomo.wait();
            let _ = remove_cleanweb_routes();
            let _ = restore_dns();
            return Err(value);
        }
        fs::write(runtime.join("mihomo.pid"), mihomo.id().to_string()).map_err(error)?;
        fs::write(runtime.join("xray.pid"), xray.id().to_string()).map_err(error)?;
        supervise_stack(mihomo, xray, binary, config, xray_binary, xray_config);
        return Ok(());
    }
    let mut child = spawn_installed_core(&binary, &config, &log, false)?;
    fs::write(runtime.join("mihomo.pid"), child.id().to_string()).map_err(error)?;
    if !Path::new(DNS_BACKUP_FILE).is_file() {
        if let Err(value) = configure_cleanweb_dns() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(value);
        }
    }
    supervise_core(child, binary, config, log);
    Ok(())
}

fn spawn_xray(
    binary: &Path,
    config: &Path,
    log_path: &Path,
    truncate: bool,
) -> Result<std::process::Child, String> {
    let log = OpenOptions::new()
        .create(true)
        .write(true)
        .append(!truncate)
        .truncate(truncate)
        .open(log_path)
        .map_err(error)?;
    fs::set_permissions(log_path, fs::Permissions::from_mode(0o644)).map_err(error)?;
    let stderr = log.try_clone().map_err(error)?;
    Command::new(binary)
        .arg("run")
        .arg("-config")
        .arg(config)
        .current_dir(SYSTEM_RUNTIME_DIR)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(error)
}

fn supervise_stack(
    mut mihomo: std::process::Child,
    mut xray: std::process::Child,
    mihomo_binary: PathBuf,
    mihomo_config: PathBuf,
    xray_binary: PathBuf,
    xray_config: PathBuf,
) {
    thread::spawn(move || {
        let runtime = Path::new(SYSTEM_RUNTIME_DIR);
        let mut mihomo_restarts = 0_u32;
        let mut xray_restarts = 0_u32;
        loop {
            if !Path::new(DESIRED_RUNNING_FILE).is_file() {
                let _ = mihomo.kill();
                let _ = xray.kill();
                let _ = mihomo.wait();
                let _ = xray.wait();
                break;
            }
            if mihomo.try_wait().ok().flatten().is_some() {
                if mihomo_restarts >= MAX_CRASH_RESTARTS {
                    break;
                }
                thread::sleep(restart_delay(mihomo_restarts));
                mihomo_restarts += 1;
                match spawn_installed_core(
                    &mihomo_binary,
                    &mihomo_config,
                    &runtime.join("mihomo.log"),
                    false,
                ) {
                    Ok(child) => {
                        mihomo = child;
                        let _ = fs::write(runtime.join("mihomo.pid"), mihomo.id().to_string());
                    }
                    Err(value) => eprintln!("CleanWeb failed to restart Mihomo: {value}"),
                }
            }
            if xray.try_wait().ok().flatten().is_some() {
                if xray_restarts >= MAX_CRASH_RESTARTS {
                    break;
                }
                thread::sleep(restart_delay(xray_restarts));
                xray_restarts += 1;
                let _ = remove_cleanweb_routes();
                match spawn_xray(&xray_binary, &xray_config, &runtime.join("xray.log"), false) {
                    Ok(mut child) => {
                        let route_result = xray_tun_name(&xray_config).and_then(|name| {
                            wait_for_tun_and_configure_routes(&name, &mihomo_config)
                        });
                        if let Err(value) = route_result {
                            let _ = child.kill();
                            let _ = child.wait();
                            eprintln!("CleanWeb failed to restore TUN routes: {value}");
                            continue;
                        }
                        xray = child;
                        let _ = fs::write(runtime.join("xray.pid"), xray.id().to_string());
                    }
                    Err(value) => eprintln!("CleanWeb failed to restart Xray: {value}"),
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
        let _ = fs::remove_file(DESIRED_RUNNING_FILE);
        let _ = mihomo.kill();
        let _ = xray.kill();
        let _ = mihomo.wait();
        let _ = xray.wait();
        let _ = fs::remove_file(runtime.join("mihomo.pid"));
        let _ = fs::remove_file(runtime.join("xray.pid"));
        let _ = remove_cleanweb_routes();
        if let Err(value) = restore_dns() {
            eprintln!("CleanWeb failed to restore DNS after stack shutdown: {value}");
        }
    });
}

fn spawn_installed_core(
    binary: &Path,
    config: &Path,
    log_path: &Path,
    truncate: bool,
) -> Result<std::process::Child, String> {
    let log = OpenOptions::new()
        .create(true)
        .write(true)
        .append(!truncate)
        .truncate(truncate)
        .open(log_path)
        .map_err(error)?;
    fs::set_permissions(log_path, fs::Permissions::from_mode(0o644)).map_err(error)?;
    let stderr = log.try_clone().map_err(error)?;
    Command::new(binary)
        .arg("-d")
        .arg(SYSTEM_RUNTIME_DIR)
        .arg("-f")
        .arg(config)
        .env("SAFE_PATHS", config.parent().ok_or("配置目录无效")?)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(error)
}

fn supervise_core(
    mut child: std::process::Child,
    binary: PathBuf,
    config: PathBuf,
    log_path: PathBuf,
) {
    thread::spawn(move || {
        for attempt in 0..=MAX_CRASH_RESTARTS {
            let _ = child.wait();
            if !Path::new(DESIRED_RUNNING_FILE).is_file() {
                let _ = fs::remove_file(Path::new(SYSTEM_RUNTIME_DIR).join("mihomo.pid"));
                let _ = restore_dns();
                return;
            }
            if attempt == MAX_CRASH_RESTARTS {
                break;
            }
            thread::sleep(restart_delay(attempt));
            match spawn_installed_core(&binary, &config, &log_path, false) {
                Ok(restarted) => {
                    child = restarted;
                    let _ = fs::write(
                        Path::new(SYSTEM_RUNTIME_DIR).join("mihomo.pid"),
                        child.id().to_string(),
                    );
                }
                Err(value) => eprintln!("CleanWeb failed to restart Mihomo: {value}"),
            }
        }
        let _ = fs::remove_file(DESIRED_RUNNING_FILE);
        let _ = fs::remove_file(Path::new(SYSTEM_RUNTIME_DIR).join("mihomo.pid"));
        if let Err(value) = restore_dns() {
            eprintln!("CleanWeb failed to restore DNS after restart exhaustion: {value}");
        }
    });
}

fn restart_delay(attempt: u32) -> Duration {
    Duration::from_secs(1_u64 << attempt.min(3))
}

fn validate_source(value: &str, expected_name: &str) -> Result<PathBuf, String> {
    validate_source_in(value, expected_name, "mihomo")
}

fn validate_source_in(
    value: &str,
    expected_name: &str,
    expected_directory: &str,
) -> Result<PathBuf, String> {
    let path = fs::canonicalize(value).map_err(error)?;
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name) {
        return Err("特权服务拒绝了意外的源文件".into());
    }
    let parent = path.parent().ok_or("源文件目录无效")?;
    let expected_suffix =
        Path::new("Library/Application Support/app.cleanweb.desktop").join(expected_directory);
    if !parent.ends_with(expected_suffix) {
        return Err("特权服务仅允许读取 CleanWeb 数据目录".into());
    }
    Ok(path)
}

fn stop_core(requested_pid: Option<u32>) -> Result<(), String> {
    let _ = fs::remove_file(DESIRED_RUNNING_FILE);
    let pid_path = Path::new(SYSTEM_RUNTIME_DIR).join("mihomo.pid");
    let saved_pid = fs::read_to_string(&pid_path)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    let xray_pid_path = Path::new(SYSTEM_RUNTIME_DIR).join("xray.pid");
    let saved_xray_pid = fs::read_to_string(&xray_pid_path)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    for pid in requested_pid
        .into_iter()
        .chain(saved_pid)
        .chain(saved_xray_pid)
        .collect::<std::collections::BTreeSet<_>>()
    {
        if is_cleanweb_core(pid) {
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            for _ in 0..20 {
                if !process_running(pid) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            if process_running(pid) {
                unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            }
        }
    }
    let _ = fs::remove_file(pid_path);
    let _ = fs::remove_file(xray_pid_path);
    remove_cleanweb_routes()?;
    restore_dns()
}

fn saved_core_running() -> bool {
    let mihomo_running = fs::read_to_string(Path::new(SYSTEM_RUNTIME_DIR).join("mihomo.pid"))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .is_some_and(|pid| process_running(pid) && is_cleanweb_core(pid));
    if !mihomo_running {
        return false;
    }
    if !Path::new(SYSTEM_RUNTIME_DIR).join("xray").is_file() {
        return true;
    }
    fs::read_to_string(Path::new(SYSTEM_RUNTIME_DIR).join("xray.pid"))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .is_some_and(|pid| process_running(pid) && is_cleanweb_core(pid))
}

fn configure_cleanweb_dns() -> Result<(), String> {
    let interface = default_interface()?;
    let service = network_service_for_interface(&network_service_order()?, &interface)
        .ok_or_else(|| format!("无法找到网卡 {interface} 对应的 macOS 网络服务"))?;
    // The service may reapply DNS after an Xray restart. Preserve the real
    // pre-CleanWeb resolver only once; otherwise 127.0.0.1 would overwrite the
    // backup and protection could not restore the user's network correctly.
    if !Path::new(DNS_BACKUP_FILE).is_file() {
        let output = Command::new("/usr/sbin/networksetup")
            .args(["-getdnsservers", &service])
            .output()
            .map_err(error)?;
        if !output.status.success() {
            return Err(format!(
                "无法读取网络服务 {service} 的 DNS：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let servers = text
            .lines()
            .map(str::trim)
            .filter(|line| line.parse::<std::net::IpAddr>().is_ok())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let backup = DnsBackup {
            service: service.clone(),
            servers,
        };
        fs::write(DNS_BACKUP_FILE, serde_json::to_vec(&backup).map_err(error)?).map_err(error)?;
        fs::set_permissions(DNS_BACKUP_FILE, fs::Permissions::from_mode(0o600)).map_err(error)?;
    }
    let status = Command::new("/usr/sbin/networksetup")
        .args(["-setdnsservers", &service, "127.0.0.1"])
        .status()
        .map_err(error)?;
    if !status.success() {
        return Err(format!("无法为网络服务 {service} 设置 CleanWeb DNS"));
    }
    Ok(())
}

fn restore_dns() -> Result<(), String> {
    let path = Path::new(DNS_BACKUP_FILE);
    let Ok(bytes) = fs::read(path) else {
        return Ok(());
    };
    let backup: DnsBackup = serde_json::from_slice(&bytes).map_err(error)?;
    let mut command = Command::new("/usr/sbin/networksetup");
    command.arg("-setdnsservers").arg(&backup.service);
    if backup.servers.is_empty() {
        command.arg("empty");
    } else {
        command.args(&backup.servers);
    }
    let status = command.status().map_err(error)?;
    if !status.success() {
        return Err(format!("无法恢复网络服务 {} 的 DNS", backup.service));
    }
    fs::remove_file(path).map_err(error)?;
    Ok(())
}

fn default_interface() -> Result<String, String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(error)?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "无法识别默认网络接口".into())
}

fn network_service_order() -> Result<String, String> {
    let output = Command::new("/usr/sbin/networksetup")
        .arg("-listnetworkserviceorder")
        .output()
        .map_err(error)?;
    if !output.status.success() {
        return Err("无法读取 macOS 网络服务列表".into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn network_service_for_interface(output: &str, interface: &str) -> Option<String> {
    let mut service = None;
    for line in output.lines().map(str::trim) {
        if line.starts_with('(') && !line.starts_with("(Hardware Port:") {
            service = line
                .split_once(')')
                .map(|(_, name)| name.trim().trim_start_matches("(*)").trim().to_owned())
                .filter(|name| !name.is_empty());
        } else if line.contains(&format!("Device: {interface}")) {
            return service;
        }
    }
    None
}

fn process_running(pid: u32) -> bool {
    (unsafe { libc::kill(pid as i32, 0) }) == 0
}

fn is_cleanweb_core(pid: u32) -> bool {
    Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|command| {
            command.contains(&format!("{SYSTEM_RUNTIME_DIR}/mihomo"))
                || command.contains(&format!("{SYSTEM_RUNTIME_DIR}/xray"))
        })
}

fn request(value: ServiceRequest) -> Result<ServiceResponse, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH).map_err(error)?;
    let mut encoded = serde_json::to_vec(&value).map_err(error)?;
    encoded.push(b'\n');
    stream.write_all(&encoded).map_err(error)?;
    let mut response = String::new();
    BufReader::new(stream)
        .take(MAX_REQUEST_BYTES)
        .read_line(&mut response)
        .map_err(error)?;
    let response: ServiceResponse = serde_json::from_str(&response).map_err(error)?;
    if response.version != PROTOCOL_VERSION {
        return Err("CleanWeb 特权服务版本不匹配".into());
    }
    if !response.ok {
        return Err(response.error.unwrap_or_else(|| "特权服务操作失败".into()));
    }
    Ok(response)
}

pub fn ping() -> bool {
    request(ServiceRequest::Ping).is_ok()
}

pub fn start(binary: &Path, config: &Path) -> Result<u32, String> {
    request(ServiceRequest::Start {
        binary: binary.display().to_string(),
        config: config.display().to_string(),
    })?
    .pid
    .ok_or_else(|| "特权服务未返回 Mihomo PID".into())
}

pub fn start_stack(
    binary: &Path,
    config: &Path,
    xray_binary: &Path,
    xray_config: &Path,
) -> Result<u32, String> {
    request(ServiceRequest::StartStack {
        binary: binary.display().to_string(),
        config: config.display().to_string(),
        xray_binary: xray_binary.display().to_string(),
        xray_config: xray_config.display().to_string(),
    })?
    .pid
    .ok_or_else(|| "特权服务未返回 Mihomo PID".into())
}

pub fn stop(pid: Option<u32>) -> Result<(), String> {
    request(ServiceRequest::Stop { pid }).map(|_| ())
}

fn error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_protocol_is_narrow_and_versioned() {
        let encoded = serde_json::to_string(&ServiceRequest::Stop { pid: Some(42) }).unwrap();
        assert_eq!(encoded, r#"{"command":"stop","pid":42}"#);
        assert_eq!(PROTOCOL_VERSION, 11);
    }

    #[test]
    fn crash_restart_backoff_is_bounded() {
        assert_eq!(restart_delay(0), Duration::from_secs(1));
        assert_eq!(restart_delay(1), Duration::from_secs(2));
        assert_eq!(restart_delay(2), Duration::from_secs(4));
        assert_eq!(restart_delay(99), Duration::from_secs(8));
    }

    #[test]
    fn finds_network_service_for_default_interface() {
        let output = "An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n(2) USB LAN\n(Hardware Port: USB 10/100/1000 LAN, Device: en7)\n";
        assert_eq!(
            network_service_for_interface(output, "en0").as_deref(),
            Some("Wi-Fi")
        );
    }

    #[test]
    fn reads_only_a_valid_utun_name_from_xray_config() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("xray.json");
        fs::write(
            &config,
            r#"{"inbounds":[{"tag":"cleanweb-tun","settings":{"name":"utun200"}}]}"#,
        )
        .unwrap();
        assert_eq!(xray_tun_name(&config).unwrap(), "utun200");
        fs::write(
            &config,
            r#"{"inbounds":[{"tag":"cleanweb-tun","settings":{"name":"en0"}}]}"#,
        )
        .unwrap();
        assert!(xray_tun_name(&config).is_err());
    }

    #[test]
    fn extracts_and_deduplicates_only_proxy_server_endpoints() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.yaml");
        fs::write(
            &config,
            r#"proxies:
- name: one
  type: ss
  server: node.example.com
  port: 443
- name: duplicate
  type: vmess
  server: node.example.com
  port: 8443
- name: literal
  type: socks5
  server: 203.0.113.7
  port: 1080
proxy-groups:
- name: CleanWeb
  type: select
  proxies: [one]
rules:
- MATCH,CleanWeb
"#,
        )
        .unwrap();

        assert_eq!(
            proxy_server_hosts(&config),
            Ok(BTreeSet::from([
                "203.0.113.7".to_owned(),
                "node.example.com".to_owned()
            ]))
        );
    }

    #[test]
    fn does_not_install_proxy_endpoint_routes_when_proxy_is_off() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.yaml");
        fs::write(
            &config,
            "proxies:\n- name: one\n  server: 203.0.113.7\n  port: 443\nrules:\n- MATCH,DIRECT\n",
        )
        .unwrap();

        assert_eq!(proxy_server_hosts(&config), Ok(BTreeSet::new()));
    }

    #[test]
    fn parses_physical_default_route_for_proxy_bypass() {
        let route = parse_default_route(
            "   route to: default\ndestination: default\n    gateway: 10.0.0.1\n  interface: en0\n",
        )
        .unwrap();
        assert_eq!(route.gateway, "10.0.0.1");
        assert_eq!(route.interface, "en0");
    }
}
