# Android Platform

Android lives in:

```text
apps/android/
```

Android owns the native VPN lifecycle through `VpnService`, foreground service notifications, Android permission flows, Android Keystore, and always-on VPN guidance.

Shared CleanWeb policy behavior should be consumed from `crates/` only after the Android Mihomo data path is validated on real devices.
