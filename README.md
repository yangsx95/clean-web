# CleanWeb

English | [简体中文](README.zh-CN.md)

CleanWeb is a local-first desktop app for network filtering, safe-search enforcement, proxy subscription import, routing policy, and access logs. It is built with Tauri, React, TypeScript, and Rust, and uses Mihomo as the controlled TUN/DNS/proxy execution core.

CleanWeb does not sell or provide proxy nodes. Users import their own proxy subscriptions, while CleanWeb keeps filtering rules, DNS, TUN, routing, and logs under the app's local policy model.

> Status: `0.1.0` beta. The app is suitable for development and real-network testing. Signed notarized macOS builds, Windows service hardening, full release license notices, and broader device validation are still in progress.

## Features

- Local content filtering with built-in rules, custom block/allow rules, and rule subscriptions.
- Safe-search enforcement for supported search providers through controlled DNS and host mappings.
- Proxy subscription import for Clash/Mihomo-style subscriptions, single-node links, and QR-code images.
- Proxy subscription sanitization: imported subscriptions keep proxy nodes and groups, while DNS, TUN, scripts, routing rules, local ports, and controller settings are discarded.
- User-defined routing rules for direct or proxied traffic.
- Locked mode that hides configuration and shows only running status and counters.
- Local access logs with retention, filtering, clearing, and CSV export.
- macOS and Windows desktop build workflows.
- Static product website under `website/`, deployable with GitHub Pages.

## Product Boundaries

CleanWeb V1 observes domains, DNS queries, target IPs, IPv4/IPv6 CIDR ranges, and Mihomo network events. It does not decrypt HTTPS traffic and does not inspect page text, images, videos, AI conversations, or full HTTPS URL paths.

Filtering decisions must run before proxy routing. Proxy subscriptions are input data, not policy authority.

Read the product and architecture documents before changing behavior:

- [Product spec](docs/product-spec.md)
- [Architecture](docs/architecture.md)
- [Implementation status](docs/implementation-status.md)

## Tech Stack

- Desktop shell: Tauri 2
- Frontend: React 19, TypeScript, Vite
- Backend: Rust
- Network core: Mihomo, distributed as a separate executable resource
- Storage: SQLite through the Rust backend
- Tests: Vitest and Rust tests

## Requirements

- Node.js 22+
- npm
- Rust stable toolchain
- Tauri 2 system dependencies for your platform
- macOS 13+ for the primary development target
- Windows 10 22H2 / Windows 11 for Windows validation

## Development

Install dependencies:

```bash
npm install
```

Run the frontend dev server:

```bash
npm run dev
```

Run the Tauri desktop app:

```bash
npm run tauri dev
```

Run checks:

```bash
npm test
npm run build
cd src-tauri && cargo test
cd src-tauri && cargo clippy --all-targets -- -D warnings
```

## Build

Build the desktop app locally:

```bash
npm run tauri -- build
```

Build macOS Universal DMG:

```bash
npm run tauri -- build --target universal-apple-darwin --bundles dmg
```

Build Windows NSIS installer on Windows:

```bash
npm run tauri -- build --bundles nsis
```

The GitHub Actions workflow in [.github/workflows/desktop-build.yml](.github/workflows/desktop-build.yml) builds unsigned Windows and macOS artifacts. Pushing a `v*` tag publishes those artifacts to GitHub Releases.

## Website

The product website lives in [website](website).

Preview it locally:

```bash
cd website
python3 -m http.server 1432 --bind 127.0.0.1
```

GitHub Pages deployment is configured in [.github/workflows/pages.yml](.github/workflows/pages.yml). In the repository settings, set Pages source to GitHub Actions.

## Release Notes

Current build artifacts are unsigned. Before public production distribution, complete:

- macOS Developer ID signing and notarization.
- Windows signing and Windows Service hardening.
- Real network validation for TUN, DNS, proxy routing, safe search, access logs, crash recovery, and uninstall recovery.
- Third-party notices and corresponding source obligations for Mihomo.
- License and redistribution review for bundled and official rule sources.

## License

The project license has not been added yet.

Mihomo is distributed as a separate GPLv3 executable resource. Releasing CleanWeb with Mihomo requires accurate version attribution, license notices, and corresponding source-code obligations. Rule sources also need explicit license and redistribution review before being presented as official CleanWeb resources.
