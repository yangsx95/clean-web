# CleanWeb development handoff

Updated: 2026-07-11 (Asia/Shanghai)

## Active objective

Finish the macOS 13+ CleanWeb MVP with:

- Real parent authentication and persistent settings
- Rule and proxy subscriptions
- Mihomo proxy protocols and proxy groups
- TUN and fake-IP DNS
- Real traffic blocking
- Access logs
- Every agreed policy switch and VPN/TUN conflict warning
- Automatic rule updates
- One universal installer for Intel and Apple Silicon Macs
- End-to-end verification proving the above

Windows is intentionally deferred. Do not call the project complete until every
item above is implemented and verified against real traffic.

## Implemented and verified

- Tauri 2 + React/TypeScript + Rust application skeleton.
- macOS Apple Silicon `.app` and `.dmg` build path.
- First-run parent password setup.
- Argon2 password hash stored in SQLite; plaintext password is not stored.
- In-memory 15-minute administrator sessions.
- SQLite-backed settings for master protection, proxy, automatic node selection,
  access logging, log retention, and content categories.
- Exact domain, suffix, substring, wildcard, regex, IP, and CIDR rule matching.
- Rule import for Clash/Mihomo lines, basic Adblock domain rules, hosts files,
  plain domain lists, and IP/CIDR lists.
- SQLite-backed rule/proxy subscription create, list, enable, disable, delete.
- Real subscription download with a 30-second timeout and 20 MB limit.
- Automatic rule format detection and normalized imported-rule persistence.
- Proxy subscription sanitization: only `proxies` and `proxy-groups` survive from
  Clash YAML; remote DNS, TUN, routing rules, and scripts are discarded.
- Base64/plain URI-list proxy subscription recognition.
- Sanitized proxy payloads are encrypted before SQLite persistence with
  AES-256-GCM; the data key is stored in the system credential store
  (macOS Keychain on macOS), and old plaintext rows are encrypted on startup.
- Manual refresh and due-subscription refresh while the UI process is running.
- UI contains real switches and real persisted subscription rows; fake counts,
  nodes, and latency values were removed.

Last verified commands:

```bash
source "$HOME/.cargo/env"
cargo test --manifest-path src-tauri/Cargo.toml
npm test
npm run build
```

Expected current results: 16 Rust tests and 6 frontend tests pass.

## Not implemented yet

1. Complete canonical node parsing for URI-list subscriptions. Clash YAML retains
   all Mihomo-supported node types, but URI lists are currently only recognized
   and counted.
2. Mihomo binary packaging and lifecycle management.
3. Generated locked Mihomo configuration and control API integration.
4. Proxy node/group selection and actual latency testing.
5. Privileged macOS helper/network extension for TUN and route/DNS changes.
6. fake-IP DNS, DNS hijacking, DoH/DoT bypass handling, and browser-policy safe-search validation.
7. Real traffic decisions wired from normalized rules into Mihomo.
8. Real access log ingestion, retention cleanup, filtering, and export.
9. Detection and warning for another VPN/TUN interface.
10. Protection continuing after the UI window/process exits.
11. Custom parent black/white rule CRUD UI.
12. Signed automatic rule packages and license/source catalog.
13. Intel build and universal single DMG.
14. Apple Developer signing, notarization, and macOS 13 Intel/ARM end-to-end tests.

## Mihomo artifact status

Target upstream release: `MetaCubeX/mihomo` `v1.19.28`.

Official expected artifacts and SHA-256 values:

- `mihomo-darwin-arm64-v1.19.28.gz`
  `40cdae2fab4b18df15f40eaa9dc3af70ab3d8be7f77164ae1e5f1af3a2a4fb44`
- `mihomo-darwin-amd64-compatible-v1.19.28.gz`
  `a469cc2f6800e71b50eca3f74bc72a8f6f7e990a5d4aaecb81a68cf331516d9d`

Downloads from the official GitHub release repeatedly timed out on this machine.
No incomplete binary is intentionally retained. Do not use an unofficial mirror.
Retry with `gh release download` or an HTTP client that supports reliable resume,
then verify both hashes before unpacking or committing artifacts.

## Recommended next sequence

1. Finish canonical proxy node/group persistence and tests.
2. Fetch and verify both official Mihomo binaries.
3. Implement a `mihomo` Rust module for config generation, process lifecycle,
   control API health, and latency tests without enabling TUN yet.
4. Implement the privileged macOS helper/network-extension design; do not fake
   protection by merely toggling the persisted switch.
5. Wire TUN, fake-IP DNS, generated blocking rules, logs, and failure recovery.
6. Add universal targets and run the requirement-by-requirement completion audit.

## Build prerequisites

- Node.js and npm
- Rust stable with Cargo
- Xcode command-line tools

```bash
npm install
source "$HOME/.cargo/env"
npm test
cargo test --manifest-path src-tauri/Cargo.toml
npm run tauri dev
```

The current release build uses an ad-hoc signature for local testing:

```bash
APPLE_SIGNING_IDENTITY="-" npm run tauri build
```

## Product and architecture references

- `docs/product-spec.md`
- `docs/architecture.md`
- `src-tauri/src/storage.rs`
- `src-tauri/src/rules.rs`
- `src-tauri/src/subscriptions.rs`
- `src-tauri/src/subscription_download.rs`
