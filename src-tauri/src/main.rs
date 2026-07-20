#[cfg(target_os = "windows")]
fn ensure_admin() {
    use std::os::windows::ffi::OsStrExt;
    use std::process::exit;

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: isize,
            desired_access: u32,
            token_handle: *mut isize,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: isize,
            token_information_class: u32,
            token_information: *mut std::ffi::c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn CloseHandle(handle: isize) -> i32;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: isize,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> isize;
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION: u32 = 20;
    const SW_SHOWNORMAL: i32 = 1;

    let elevated = unsafe {
        let mut token: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            false
        } else {
            let mut elevation = TokenElevation {
                token_is_elevated: 0,
            };
            let mut ret_size: u32 = 0;
            let result = GetTokenInformation(
                token,
                TOKEN_ELEVATION,
                &mut elevation as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<TokenElevation>() as u32,
                &mut ret_size,
            );
            CloseHandle(token);
            result != 0 && elevation.token_is_elevated != 0
        }
    };

    if elevated {
        return;
    }

    let exe = std::env::current_exe().unwrap_or_default();
    let exe_path: Vec<u16> = std::ffi::OsStr::new(&exe)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();

    unsafe {
        ShellExecuteW(
            0,
            verb.as_ptr(),
            exe_path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
    exit(0);
}

fn main() {
    // Release 构建自动请求管理员权限（TUN 需要）；
    // Debug/Dev 模式跳过，请用管理员终端运行 `npm run tauri dev`。
    #[cfg(all(target_os = "windows", not(debug_assertions)))]
    ensure_admin();
    cleanweb_lib::run()
}
