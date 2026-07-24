# CleanWeb Mobile

This is the Tauri mobile application shell for Android and iOS management UI.

The mobile app reuses the desktop React management interface from `apps/desktop/src`.
Platform VPN execution must remain native and be exposed through narrow Tauri plugins:

- Android: `VpnService`, foreground service lifecycle, `tun2socks`, and Mihomo process control.
- iOS: Network Extension Packet Tunnel Provider.

The existing `apps/android` Kotlin app remains a transition prototype and a source for the Android VPN plugin boundary. New product UI work should land in the shared React surface instead of expanding the Compose prototype.

## Commands

From the repository root:

```bash
npm run dev:mobile
npm run build:mobile
```

Tauri mobile setup should be initialized from this directory when the native Android/iOS shell is generated:

```bash
npm run tauri:mobile -- android init
npm run tauri:mobile -- ios init
```
