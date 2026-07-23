# Desktop Platform

Desktop covers macOS, Windows, and future Linux support under one product surface:

```text
apps/desktop/
  src/                    # Shared React management UI
  src-tauri/              # Rust/Tauri backend
```

Platform-specific system integration should live behind Rust platform adapters. The current implementation has `platform.rs`; as Linux support grows, split it into:

```text
apps/desktop/src-tauri/src/platform/
  mod.rs
  macos.rs
  windows.rs
  linux.rs
```

Desktop owns privileged service installation, TUN/DNS lifecycle, Mihomo process management, system route recovery, and desktop packaging.
