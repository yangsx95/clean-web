# CleanWeb Android

Android 10+ native prototype for CleanWeb.

This project intentionally lives beside the Tauri desktop app under `apps/` instead of inside `apps/desktop/src-tauri`. Android owns the platform VPN lifecycle through `VpnService`; shared CleanWeb policy formats and rule behavior should be moved into reusable modules only after the Android data path is validated.

## Scope

Current scaffold:

- Kotlin + Jetpack Compose app shell.
- Android `VpnService` declaration.
- VPN permission request flow.
- Foreground service notification placeholder.

Not implemented yet:

- Mihomo Android runtime integration.
- TUN packet forwarding.
- Rule compilation and subscription import.
- Access log persistence.
- Android Keystore encryption.
- Always-on VPN / lockdown deep-link guidance.

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

1. Add a real Mihomo Android artifact or native library packaging strategy.
2. Start Mihomo behind `CleanWebVpnService` without exposing local proxy ports.
3. Validate DNS interception, rule blocking, safe-search hosts mapping, and proxy routing with real device traffic.
4. Decide whether Rust rule and subscription modules should be reused through JNI/UniFFI or mirrored in Kotlin for the first Android MVP.
