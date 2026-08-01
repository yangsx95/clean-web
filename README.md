# CleanWeb

English | [简体中文](README.zh-CN.md)

CleanWeb is a local-first desktop app for content filtering, safe-search enforcement, proxy subscription management, routing policy, and local access logs.

- Website: [https://yangsx95.github.io/clean-web/](https://yangsx95.github.io/clean-web/)
- Download: [GitHub Releases](https://github.com/yangsx95/clean-web/releases/latest)
- Current version: `0.1.0` beta
- Platforms: macOS 13+ first, Windows 10 22H2 / Windows 11 in validation, Android/iOS via the Tauri mobile shell in [apps/mobile](apps/mobile)

> Beta notice: current builds are for testing and real-network validation. macOS signing/notarization, Windows service hardening, complete license notices, and broader device testing are still in progress.

## What It Does

CleanWeb helps families and self-control users manage device network access from one desktop app:

- Block unwanted domains, IPs, and rule subscription entries.
- Enforce safe-search mode for supported search providers.
- Import your own proxy subscriptions and proxy nodes.
- Decide which allowed traffic goes direct or through a proxy.
- Keep a local access log with counters, filtering, export, and retention.
- Lock sensitive settings behind a management password.

CleanWeb does **not** sell proxy nodes, host proxy services, or decrypt HTTPS traffic.

## How It Works

CleanWeb uses a local policy engine and Mihomo as a controlled TUN/DNS/proxy execution core. Filtering rules are applied before proxy routing, so a proxy subscription cannot bypass CleanWeb's content policy.

When a proxy subscription is imported, CleanWeb keeps only proxy nodes and proxy groups. DNS, TUN, scripts, routing rules, local ports, and controller settings from the subscription are discarded.

## Product Boundaries

CleanWeb V1 can observe domains, DNS queries, target IPs, IPv4/IPv6 CIDR ranges, and Mihomo network events. It does not inspect page text, images, videos, AI conversations, or full HTTPS URL paths.

For detailed product and architecture boundaries, see:

- [Product spec](docs/product-spec.md)
- [Architecture](docs/architecture.md)
- [Implementation status](docs/implementation-status.md)
- [Project structure](docs/project-structure.md)

## For Developers

CleanWeb is built with:

- Tauri 2
- React 19, TypeScript, Vite
- Rust
- Tauri mobile for Android/iOS shells
- Mihomo as a separate executable resource
- SQLite through the Rust backend
- Vitest and Rust tests

Install dependencies:

```bash
mise trust
mise install
mise run install
```

Run the desktop app:

```bash
mise run dev
```

Run checks:

```bash
mise run check
```

## Build

Build locally:

```bash
mise run desktop-build
```

Build macOS Universal DMG:

```bash
mise run rust-targets-macos
mise run desktop-build-macos
```

Build Windows NSIS installer on Windows:

```bash
mise run desktop-build-windows
```

GitHub Actions uses the same mise tasks to build unsigned Windows, macOS, Android, and iOS simulator artifacts. Pushing a `v*` tag publishes those artifacts to GitHub Releases.

## Website

The product website source lives in [website](website). GitHub Pages deployment is configured in [.github/workflows/pages.yml](.github/workflows/pages.yml). In repository settings, set Pages source to GitHub Actions.

## License

The project license has not been added yet.

Mihomo is distributed as a separate GPLv3 executable resource. Releasing CleanWeb with Mihomo requires accurate version attribution, license notices, and corresponding source-code obligations. Rule sources also need explicit license and redistribution review before being presented as official CleanWeb resources.
