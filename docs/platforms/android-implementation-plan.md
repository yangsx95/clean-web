# Android implementation plan

This plan keeps the shared React UI in `packages/frontend` and puts Android network capture behind a narrow Tauri native plugin in `apps/mobile`. The first milestone is a buildable VPN permission and lifecycle bridge. Full traffic filtering requires a later data-plane milestone with Mihomo or tun2socks running behind Android `VpnService`.

## Goals

- Reuse the shared CleanWeb management UI where behavior is platform neutral.
- Keep Android VPN lifecycle native: permission prompt, foreground service, VPN service, status, and teardown.
- Keep the JavaScript/Rust boundary narrow and typed.
- Avoid opening HTTP or SOCKS proxy ports to other apps.
- Make Android builds release-gated by real device validation before publishing to users.

## Non-goals for the first milestone

- No full packet forwarding yet.
- No Android Mihomo process lifecycle yet.
- No production signing or Play Store release yet.
- No MDM/device-owner hardening.

## Milestone 1: VPN shell and Tauri bridge

Deliverables:

- Android manifest permissions for `VpnService` and foreground VPN service.
- `CleanWebVpnService` that establishes and tears down a minimal VPN interface.
- `CleanWebVpnPlugin` with Tauri commands:
  - `prepare_vpn`
  - `start_vpn`
  - `stop_vpn`
  - `vpn_status`
  - `update_policy`
- Mobile Rust commands that expose the Android VPN bridge to shared frontend code:
  - `mobile_prepare_vpn`
  - `mobile_start_vpn`
  - `mobile_stop_vpn`
  - `mobile_vpn_status`
  - `mobile_update_policy`
- Shared frontend backend helpers for mobile VPN commands.

Validation:

- `npm run build:mobile`
- Android Gradle compile/package through `npm run tauri:mobile -- android build --apk`
- GitHub Actions uploads both unsigned Android artifacts for official signing and debug-signed APKs for sideload testing. Do not install `*-unsigned.apk` directly on a device.
- On a real Android 10+ device:
  - permission prompt appears once;
  - starting protection creates Android VPN system indicator;
  - stopping protection removes the VPN and restores networking;
  - app UI does not freeze.

## Milestone 2: policy and rule payload

Status: implemented for the DNS-only data plane. The mobile frontend sends a policy snapshot with settings, manual parent rules, and rule subscription enabled states. Android validates before replacement, persists the last valid policy, applies updates without reacquiring VPN permission, and reports the last policy update time.

Deliverables:

- Serialize CleanWeb rule categories, settings, and selected proxy state into a mobile policy payload.
- Persist mobile policy in app-private Android storage.
- Add status fields for last policy update time and last service error.

Validation:

- Policy update works while VPN is stopped.
- Policy update works while VPN is running without recreating permission state.
- Invalid policy is rejected and old policy remains active.

## Milestone 3: DNS filtering data path

Status: implemented for IPv4 UDP DNS, pending real-device release validation. Android `VpnService` routes system DNS to the VPN interface, reads DNS packets from TUN, asks the Rust DNS engine for block decisions, returns NXDOMAIN for blocked domains, and forwards allowed DNS through a protected upstream socket. It preserves the active network's DNS resolvers with bounded fallback, validates DNS transaction IDs, applies desktop-equivalent security/manual/content priority, records a bounded local DNS access log, and reports query/block/upstream-failure counters. The data path covers manual domain rules, Android-local rule subscription download/storage/refresh, and SafeSearch DNS mapping answers.

Deliverables:

- Route DNS traffic through the VPN service.
- Reuse shared rule parsing and compiled domain index where feasible.
- Return NXDOMAIN or safe-search DNS answers for matching domains.

Validation:

- Real DNS queries for blocked domains fail.
- Allowed domains resolve normally.
- Safe-search DNS mappings work on Android browsers that use system DNS.
- DNS failures fail open only when service startup cannot complete.

## Milestone 4: proxy and full tunnel data path

Status: not implemented. The current Android service intentionally remains DNS-only; routing `0.0.0.0/0` before a TCP/UDP forwarding path exists would break normal networking. Full tunnel must be implemented by integrating Mihomo or tun2socks behind `VpnService`, with CleanWeb DNS filtering still evaluated before proxy routing.

Deliverables:

- Integrate Mihomo or tun2socks behind `VpnService`.
- CleanWeb policy remains authoritative over filtering and proxy rules.
- Proxy subscription content remains sanitized before entering the data path.

Validation:

- Allowed traffic can route direct or through selected proxy.
- Blocked domains are blocked before proxy routing.
- Proxy node changes do not freeze the UI.
- Service crash recovers or clearly reports failure.

## Milestone 5: release readiness

Deliverables:

- Android release build in CI.
- Signing workflow documented.
- Device validation checklist recorded for each release candidate.

Release gate:

- Do not publish Android to users until real-device VPN capture, DNS filtering, proxy routing, teardown, reboot, and upgrade recovery pass.
