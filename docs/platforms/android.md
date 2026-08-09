# Android Platform

Android platform execution currently lives in:

```text
apps/mobile/
```

Android product UI is the Tauri mobile shell mounted from `packages/frontend`.

Android owns only the native VPN lifecycle through a Tauri Android plugin: `VpnService`, foreground service notifications, Android permission flows, Android Keystore, `tun2socks`, Mihomo lifecycle, and always-on VPN guidance.

Do not add a second Android app directory or a separate management UI. Android-specific packet capture must stay behind narrow Tauri plugin commands called from `apps/mobile`.

The Android plugin should expose only narrow operations to the shared Tauri mobile UI:

- request VPN permission;
- start protection with a validated CleanWeb policy/config bundle;
- stop protection and restore network state;
- restart protection after policy changes;
- report running, starting, failed, and permission-denied states;
- expose sanitized diagnostics and local startup logs.

Current implementation is deliberately DNS-only: it routes only the CleanWeb DNS address into `VpnService`, so normal TCP/UDP traffic continues through Android's existing route. The status API must expose this as `dns_only` and must not present it as the desktop-equivalent full tunnel. Allowed DNS is forwarded first to resolvers captured from the active network, which preserves enterprise/VPN split DNS where Android exposes it; public resolvers are fallback only.

Do not place rule parsing, proxy subscription cleaning, category policy, or management UI in Android-specific code. Those belong in shared Rust crates and `packages/frontend`.
