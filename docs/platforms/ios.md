# iOS Platform

iOS product UI should share:

```text
apps/mobile/
```

The expected platform execution is a native Network Extension Packet Tunnel Provider exposed to the shared mobile UI through a Tauri iOS plugin.

Do not add a separate iOS app directory. iOS-specific packet capture should stay behind a Tauri iOS plugin and Packet Tunnel Provider boundary once Apple entitlement approval, App Store VPN and parental-control policy review, Mihomo packaging feasibility inside the extension, resource limits, and license review are confirmed.

When work starts, the iOS plugin should expose only narrow operations to the shared Tauri mobile UI:

- request and install VPN configuration;
- start and stop the packet tunnel;
- apply validated CleanWeb policy/config bundles;
- report tunnel health and sanitized diagnostics.

Shared policy and UI must remain outside the extension.
