# CleanWeb

CleanWeb is a Windows-first parental network filtering client. It combines a
local policy engine with an independently distributed proxy core so families
can use network proxies without losing domain and IP filtering.

## V1 scope

- System-wide traffic capture on Windows
- Parent-locked configuration
- Domain, wildcard, regex, IP, and CIDR filtering
- Commercially compatible community rule subscriptions
- Proxy node and proxy-group import only
- Local access logs with configurable retention
- Safe-search enforcement for common search providers

See [docs/product-spec.md](docs/product-spec.md) and
[docs/architecture.md](docs/architecture.md) for the agreed product boundary.

## Development

```bash
npm install
npm run dev
npm test
```

The desktop shell additionally requires the Rust toolchain and Tauri system
dependencies:

```bash
npm run tauri dev
```
