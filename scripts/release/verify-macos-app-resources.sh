#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: scripts/release/verify-macos-app-resources.sh /path/to/CleanWeb.app" >&2
  exit 2
fi

APP="$1"
if [[ ! -d "$APP" ]]; then
  echo "App bundle not found: $APP" >&2
  exit 2
fi

RESOURCES="$APP/Contents/Resources"
EXECUTABLE="$APP/Contents/MacOS/cleanweb"
CONFIG="$RESOURCES/rule-sources/defaults.yaml"

required_files=(
  "$CONFIG"
  "$RESOURCES/rules/cleanweb-adult-supplement.clash"
  "$RESOURCES/rules/cleanweb-security-supplement.clash"
  "$RESOURCES/rules/cleanweb-safe-search.yaml"
  "$RESOURCES/rules/cleanweb-entertainment-short-video.clash"
  "$RESOURCES/rules/cleanweb-entertainment-social.clash"
  "$RESOURCES/rules/cleanweb-entertainment-games.clash"
  "$RESOURCES/rules/cleanweb-strict-adult-keywords.clash"
  "$RESOURCES/rules/cleanweb-strict-gambling-keywords.clash"
  "$RESOURCES/rules/cleanweb-strict-restricted-platforms.clash"
  "$RESOURCES/rules/cleanweb-strict-risky-tlds.clash"
)

for file in "${required_files[@]}"; do
  if [[ ! -s "$file" ]]; then
    echo "Required CleanWeb resource is missing or empty: $file" >&2
    exit 1
  fi
done

if [[ ! -x "$EXECUTABLE" ]]; then
  echo "CleanWeb executable is missing: $EXECUTABLE" >&2
  exit 1
fi

ARCHS="$(lipo -archs "$EXECUTABLE")"
MIHOMO_DIR="$RESOURCES/resources/mihomo"
if [[ " $ARCHS " == *" arm64 " ]] && ! compgen -G "$MIHOMO_DIR/mihomo-darwin-arm64-*.gz" >/dev/null; then
  echo "The arm64 app is missing its arm64 Mihomo archive." >&2
  exit 1
fi
if [[ " $ARCHS " == *" x86_64 " ]] && ! compgen -G "$MIHOMO_DIR/mihomo-darwin-amd64-*.gz" >/dev/null; then
  echo "The x86_64 app is missing its amd64 Mihomo archive." >&2
  exit 1
fi
if compgen -G "$MIHOMO_DIR/mihomo-windows-*.gz" >/dev/null; then
  echo "The macOS app incorrectly contains Windows Mihomo archives." >&2
  exit 1
fi

echo "Verified CleanWeb macOS resources for architectures: $ARCHS"
