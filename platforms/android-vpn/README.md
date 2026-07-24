# Android VPN Boundary

Android traffic capture must use `VpnService`.

This boundary should expose only narrow operations to the shared Tauri mobile UI:

- request VPN permission;
- start protection with a validated CleanWeb policy/config bundle;
- stop protection and restore network state;
- restart protection after policy changes;
- report running, starting, failed, and permission-denied states;
- expose sanitized diagnostics and local startup logs.

Do not place rule parsing, proxy subscription cleaning, category policy, or management UI here. Those belong in shared Rust crates and the shared React UI.
