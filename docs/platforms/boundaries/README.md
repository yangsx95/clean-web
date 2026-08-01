# Platform Boundaries

This directory documents native system capabilities that cannot be shared as ordinary React or Rust business logic. It is documentation only, not a source root.

Shared CleanWeb behavior belongs in `crates/` and shared UI belongs in `shared/frontend`.

Platform-specific code should stay behind narrow plugin or service boundaries:

- `android-vpn/`: Android `VpnService`, foreground service, `tun2socks`, Mihomo lifecycle.
- `ios-network-extension/`: iOS Packet Tunnel Provider lifecycle.
- `desktop-privileged/`: macOS, Windows, and Linux privileged TUN/DNS/route service boundaries.
