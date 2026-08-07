#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: scripts/release/verify-macos-dmg.sh /path/to/CleanWeb.dmg" >&2
  exit 2
fi

DMG="$1"
if [[ ! -f "$DMG" ]]; then
  echo "DMG not found: $DMG" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS DMG verification requires macOS." >&2
  exit 2
fi

MOUNT_POINT="$(mktemp -d /tmp/cleanweb-dmg-verify.XXXXXX)"
ATTACHED=0
cleanup() {
  if [[ "$ATTACHED" -eq 1 ]]; then
    hdiutil detach "$MOUNT_POINT" -quiet || true
  fi
  rmdir "$MOUNT_POINT" 2>/dev/null || true
}
trap cleanup EXIT

echo "Assessing DMG with Gatekeeper: $DMG"
spctl --assess --type open --verbose=4 "$DMG"

hdiutil attach "$DMG" -nobrowse -readonly -mountpoint "$MOUNT_POINT" -quiet
ATTACHED=1

APP_COUNT="$(find "$MOUNT_POINT" -maxdepth 1 -type d -name "*.app" | wc -l | tr -d ' ')"
if [[ "$APP_COUNT" != "1" ]]; then
  echo "Expected exactly one .app in DMG, found $APP_COUNT." >&2
  find "$MOUNT_POINT" -maxdepth 1 -print >&2
  exit 1
fi

APP="$(find "$MOUNT_POINT" -maxdepth 1 -type d -name "*.app" -print -quit)"

echo "Verifying code signature: $APP"
codesign --verify --deep --strict --verbose=4 "$APP"

echo "Assessing app with Gatekeeper: $APP"
spctl --assess --type execute --verbose=4 "$APP"

echo "macOS DMG is signed and accepted by Gatekeeper."
