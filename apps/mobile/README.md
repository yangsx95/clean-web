# CleanWeb Mobile

This is the Tauri mobile application shell for Android and iOS management UI.

The mobile app reuses the shared React management interface from `packages/frontend`.
Platform VPN execution must remain native and be exposed through narrow Tauri plugins:

- Android: `VpnService`, foreground service lifecycle, `tun2socks`, and Mihomo process control.
- iOS: Network Extension Packet Tunnel Provider.

Android and iOS product work should land here or in shared frontend/Rust modules. Platform packet-capture code should be implemented as narrow Tauri native plugins, not as separate app directories.

## Commands

From the repository root:

```bash
npm run dev:mobile
npm run build:mobile
```

Tauri mobile setup is managed from this directory:

```bash
npm run tauri:mobile -- android init
npm run tauri:mobile -- ios init
```
