# Android Platform

Android platform execution currently lives in:

```text
apps/android/
```

The long-term Android product UI should live in:

```text
apps/mobile/
```

Android owns only the native VPN lifecycle through `VpnService`, foreground service notifications, Android permission flows, Android Keystore, and always-on VPN guidance.

The current Kotlin + Compose app is a transition prototype. Do not expand it into a second full management app. Once the Android Mihomo data path is validated on real devices, move the native VPN lifecycle into a Tauri Android plugin and call it from `apps/mobile`.
