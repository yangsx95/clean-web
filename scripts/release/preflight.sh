#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

npm test
npm run build

cd "$ROOT_DIR/apps/desktop/src-tauri"
cargo test
cargo clippy --all-targets -- -D warnings

