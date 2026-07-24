# iOS Network Extension Boundary

iOS traffic capture must use a Packet Tunnel Provider.

This boundary is blocked until entitlement, App Store policy, Mihomo packaging, resource limits, and license review are resolved.

When work starts, expose only narrow operations to the shared Tauri mobile UI:

- request and install VPN configuration;
- start and stop the packet tunnel;
- apply validated CleanWeb policy/config bundles;
- report tunnel health and sanitized diagnostics.

Shared policy and UI must remain outside the extension.
