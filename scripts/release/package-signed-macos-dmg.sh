#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: scripts/release/package-signed-macos-dmg.sh /path/to/CleanWeb.app-or.dmg /path/to/output.dmg" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Signed macOS DMG packaging requires macOS." >&2
  exit 2
fi

if [[ -z "${MACOS_SIGNING_IDENTITY:-}" ]]; then
  echo "MACOS_SIGNING_IDENTITY is required." >&2
  exit 2
fi

INPUT="$1"
OUTPUT="$2"

if [[ ! -e "$INPUT" ]]; then
  echo "Input not found: $INPUT" >&2
  exit 2
fi

WORK_DIR="$(mktemp -d /tmp/cleanweb-signed-dmg.XXXXXX)"
MOUNT_POINT="$(mktemp -d /tmp/cleanweb-signed-dmg-mount.XXXXXX)"
ATTACHED=0

cleanup() {
  if [[ "$ATTACHED" -eq 1 ]]; then
    hdiutil detach "$MOUNT_POINT" -quiet || true
  fi
  rm -rf "$WORK_DIR"
  rmdir "$MOUNT_POINT" 2>/dev/null || true
}
trap cleanup EXIT

APP_SOURCE=""
case "$INPUT" in
  *.app)
    if [[ ! -d "$INPUT" ]]; then
      echo "App input is not a directory: $INPUT" >&2
      exit 2
    fi
    APP_SOURCE="$INPUT"
    ;;
  *.dmg)
    if [[ ! -f "$INPUT" ]]; then
      echo "DMG input is not a file: $INPUT" >&2
      exit 2
    fi
    hdiutil attach "$INPUT" -nobrowse -readonly -mountpoint "$MOUNT_POINT" -quiet
    ATTACHED=1
    APP_COUNT="$(find "$MOUNT_POINT" -maxdepth 1 -type d -name "*.app" | wc -l | tr -d ' ')"
    if [[ "$APP_COUNT" != "1" ]]; then
      echo "Expected exactly one .app in DMG, found $APP_COUNT." >&2
      find "$MOUNT_POINT" -maxdepth 1 -print >&2
      exit 1
    fi
    APP_SOURCE="$(find "$MOUNT_POINT" -maxdepth 1 -type d -name "*.app" -print -quit)"
    ;;
  *)
    echo "Input must be a .app bundle or .dmg: $INPUT" >&2
    exit 2
    ;;
esac

STAGING="$WORK_DIR/staging"
mkdir -p "$STAGING" "$(dirname "$OUTPUT")"
ditto "$APP_SOURCE" "$STAGING/$(basename "$APP_SOURCE")"

APP="$STAGING/$(basename "$APP_SOURCE")"
xattr -cr "$APP"
/usr/libexec/PlistBuddy -c "Delete :LSRequiresCarbon" "$APP/Contents/Info.plist" 2>/dev/null || true
codesign --remove-signature "$APP" 2>/dev/null || true
codesign \
  --force \
  --deep \
  --options runtime \
  --timestamp \
  --sign "$MACOS_SIGNING_IDENTITY" \
  "$APP"
codesign --verify --deep --strict --verbose=4 "$APP"
test -f "$APP/Contents/_CodeSignature/CodeResources"

TMP_DMG="$WORK_DIR/CleanWeb-signed.dmg"
hdiutil create -volname CleanWeb -srcfolder "$STAGING" -ov -format UDZO "$TMP_DMG" -quiet
codesign --force --timestamp --sign "$MACOS_SIGNING_IDENTITY" "$TMP_DMG"

if [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
  xcrun notarytool submit "$TMP_DMG" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_SPECIFIC_PASSWORD" \
    --wait
  xcrun stapler staple "$TMP_DMG"
  spctl --assess --type open --verbose=4 "$TMP_DMG"
else
  echo "Apple notarization credentials are not configured; produced a signed but not notarized DMG." >&2
fi

ditto "$TMP_DMG" "$OUTPUT"
xattr -cr "$OUTPUT"
echo "Wrote signed macOS DMG: $OUTPUT"
