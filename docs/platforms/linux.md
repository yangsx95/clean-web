# Linux Desktop Platform

Linux belongs under the desktop app, not as a separate top-level app:

```text
apps/desktop/
```

Expected Linux-specific work should be isolated behind the desktop platform adapter:

```text
apps/desktop/src-tauri/src/platform/linux.rs
```

Linux will need separate handling for TUN permissions, DNS integration, route management, service lifecycle, packaging, and secret storage. Candidate integrations include systemd, NetworkManager, resolvectl, iproute2, and Secret Service/libsecret.
