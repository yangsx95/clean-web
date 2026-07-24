# Mobile Platform

Mobile product UI lives in:

```text
apps/mobile/
```

`apps/mobile` uses Tauri mobile and reuses the desktop React management interface. It should become the shared Android/iOS management surface for:

- management lock and unlock;
- total protection state;
- settings;
- parent rules and route rules;
- rule subscriptions;
- proxy subscriptions and node selection;
- local logs and diagnostics.

Mobile must not own platform packet capture directly. Android and iOS packet handling stays in native plugins:

- Android: `VpnService`, foreground service, `tun2socks`, Mihomo process lifecycle.
- iOS: Network Extension Packet Tunnel Provider.

Shared policy, subscription parsing, rule validation, and Mihomo config generation should move into `crates/` when both desktop and mobile need the same behavior.
