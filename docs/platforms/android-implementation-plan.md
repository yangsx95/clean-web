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
- On a real Android 10+ device:
  - permission prompt appears once;
  - starting protection creates Android VPN system indicator;
  - stopping protection removes the VPN and restores networking;
  - app UI does not freeze.

## Milestone 2: policy and rule payload

Deliverables:

- Serialize CleanWeb rule categories, settings, and selected proxy state into a mobile policy payload.
- Persist mobile policy in app-private Android storage.
- Add status fields for last policy update time and last service error.

Validation:

- Policy update works while VPN is stopped.
- Policy update works while VPN is running without recreating permission state.
- Invalid policy is rejected and old policy remains active.

## Milestone 3: DNS filtering data path

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
