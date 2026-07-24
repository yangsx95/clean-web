# CleanWeb Android VPN Prototype

Android 10+ native VPN prototype for CleanWeb.

This project is no longer the long-term Android product UI. The product UI should move to `apps/mobile` with Tauri mobile and shared React/Rust code. This directory remains the Android `VpnService` data-path prototype and the migration source for a future Tauri Android VPN plugin.

## Scope

Current scaffold:

- Kotlin + Jetpack Compose transition management shell.
- Protection, rules, proxy subscriptions, logs, and settings screens.
- Local state persistence through Android `SharedPreferences`.
- Android `VpnService` declaration.
- VPN permission request flow.
- Foreground service notification.
- Bundled Mihomo Android arm64-v8 binary.
- Full-device IPv4 VPN route through `VpnService`.
- `tun2socks` bridge from Android TUN fd to Mihomo local SOCKS.
- Mihomo config generation for local rules, proxy providers, DNS, safe-search hosts, and SNI/HTTP sniffing.
- CleanWeb app UID is excluded from the Android VPN so Mihomo proxy-provider fetches and proxy outbound sockets do not loop back into the same TUN.
- Local lifecycle logs for Android VPN, Mihomo, and tun2socks startup.

Not implemented yet:

- Tauri Android plugin boundary.
- Non-arm64 Android ABI packaging.
- Full shared Rust rule compiler and subscription import on Android.
- Connection-level access log collection from Mihomo.
- Android Keystore encryption.
- Always-on VPN / lockdown settings deep links.
- Real-device validation of proxy providers, DNS behavior, app compatibility, and recovery.

## Manual Validation

The current Android data path starts Mihomo and routes the device IPv4 default route through tun2socks into Mihomo.

1. Install `app/build/outputs/apk/debug/app-debug.apk` on an Android 10+ device.
2. Open CleanWeb, add a block rule such as `example.com`.
3. Optionally add an HTTPS proxy subscription and enable proxy routing in Settings.
4. Start protection and accept the Android VPN permission prompt.
5. Open a browser and verify ordinary sites still load.
6. Visit the blocked domain and confirm Mihomo rejects it.
7. Return to CleanWeb > Logs and confirm Android VPN/Mihomo/tun2socks startup events.

Known limits:

- Debug APK currently packages only `arm64-v8a`.
- Android cannot expose Mihomo's desktop TUN `dns-hijack` path directly in this architecture; domain filtering currently relies on DNS traffic through the VPN plus HTTP/TLS sniffing and must be verified per device/app.
- DNS-specific safe-search behavior is configured in Mihomo, but still needs real-device validation because Android DNS server selection is owned by `VpnService`.
- DoH/DoT, direct IP access, QUIC behavior, and per-connection decision logs still need real-device validation.

## Requirements

- Android Studio with Android SDK.
- JDK supported by the installed Android Gradle Plugin.
- Android 10/API 29 or newer test device or emulator.

## Build

From this directory:

```bash
./gradlew :app:assembleDebug
```

If the Gradle wrapper has not been generated yet, open this directory in Android Studio or run Gradle once locally to create the wrapper.

## Next Milestone

1. Validate the Mihomo + tun2socks tunnel on real devices.
2. Wire Mihomo controller polling into Android access logs and proxy node status.
3. Replace metadata-only proxy imports with cleaned subscription import or locked proxy providers.
4. Validate or replace the Android DNS interception strategy for safe-search parity, then add Android Keystore encryption.
5. Move the validated Android VPN lifecycle into a Tauri Android plugin.
6. Use `apps/mobile` for Android product UI instead of expanding this Compose prototype.
