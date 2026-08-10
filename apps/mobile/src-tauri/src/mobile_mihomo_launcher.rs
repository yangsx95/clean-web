#[cfg(target_os = "android")]
use std::ffi::CString;

#[cfg(target_os = "android")]
use jni::{
    objects::{JClass, JString},
    sys::{jint, jstring},
    JNIEnv,
};

#[cfg(target_os = "android")]
const MIHOMO_TUN_FD: i32 = 3;

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_app_cleanweb_mobile_CleanWebMihomoLauncher_spawnMihomo(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    executable: JString<'_>,
    runtime_dir: JString<'_>,
    config_path: JString<'_>,
    tun_fd: jint,
) -> jint {
    match spawn_mihomo(&mut env, executable, runtime_dir, config_path, tun_fd) {
        Ok(pid) => pid,
        Err(error) => {
            let _ = env.throw_new("java/lang/IllegalStateException", error);
            -1
        }
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_app_cleanweb_mobile_CleanWebMihomoLauncher_waitMihomo(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    pid: jint,
) -> jint {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            if libc::WIFEXITED(status) {
                return libc::WEXITSTATUS(status) as jint;
            }
            if libc::WIFSIGNALED(status) {
                return (128 + libc::WTERMSIG(status)) as jint;
            }
            return status as jint;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            format!("Android Mihomo waitpid failed: {error}"),
        );
        return -1;
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_app_cleanweb_mobile_CleanWebMihomoLauncher_terminateMihomo(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    pid: jint,
) {
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_app_cleanweb_mobile_CleanWebMihomoLauncher_errorString(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    code: jint,
) -> jstring {
    let value = std::io::Error::from_raw_os_error(code).to_string();
    env.new_string(value)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[cfg(target_os = "android")]
fn spawn_mihomo(
    env: &mut JNIEnv<'_>,
    executable: JString<'_>,
    runtime_dir: JString<'_>,
    config_path: JString<'_>,
    tun_fd: jint,
) -> Result<jint, String> {
    let executable = jni_string(env, executable)?;
    let runtime_dir = jni_string(env, runtime_dir)?;
    let config_path = jni_string(env, config_path)?;
    let executable_c = CString::new(executable.clone()).map_err(|error| error.to_string())?;
    let runtime_dir_c = CString::new(runtime_dir.clone()).map_err(|error| error.to_string())?;
    let config_path_c = CString::new(config_path.clone()).map_err(|error| error.to_string())?;
    let log_path_c =
        CString::new(format!("{runtime_dir}/mihomo.log")).map_err(|error| error.to_string())?;
    let arg_d = CString::new("-d").unwrap();
    let arg_f = CString::new("-f").unwrap();
    let env_home = CString::new("HOME").unwrap();
    let env_xdg_config_home = CString::new("XDG_CONFIG_HOME").unwrap();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "Android Mihomo fork failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        unsafe {
            if libc::dup2(tun_fd, MIHOMO_TUN_FD) < 0 {
                libc::_exit(121);
            }
            let flags = libc::fcntl(MIHOMO_TUN_FD, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(MIHOMO_TUN_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
            let log_fd = libc::open(
                log_path_c.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC,
                0o600,
            );
            if log_fd >= 0 {
                libc::dup2(log_fd, libc::STDOUT_FILENO);
                libc::dup2(log_fd, libc::STDERR_FILENO);
                libc::close(log_fd);
            }
            libc::chdir(runtime_dir_c.as_ptr());
            libc::setenv(env_home.as_ptr(), runtime_dir_c.as_ptr(), 1);
            libc::setenv(env_xdg_config_home.as_ptr(), runtime_dir_c.as_ptr(), 1);
            libc::execl(
                executable_c.as_ptr(),
                executable_c.as_ptr(),
                arg_d.as_ptr(),
                runtime_dir_c.as_ptr(),
                arg_f.as_ptr(),
                config_path_c.as_ptr(),
                std::ptr::null::<libc::c_char>(),
            );
            libc::_exit(122);
        }
    }
    Ok(pid as jint)
}

#[cfg(target_os = "android")]
fn jni_string(env: &mut JNIEnv<'_>, value: JString<'_>) -> Result<String, String> {
    env.get_string(&value)
        .map(|value| value.into())
        .map_err(|error| error.to_string())
}
