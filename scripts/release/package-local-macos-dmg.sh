#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: scripts/release/package-local-macos-dmg.sh /path/to/CleanWeb.app-or.dmg /path/to/output.dmg" >&2
  exit 2
fi

INPUT="$1"
OUTPUT="$2"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Local macOS DMG packaging requires macOS." >&2
  exit 2
fi

if [[ ! -e "$INPUT" ]]; then
  echo "Input not found: $INPUT" >&2
  exit 2
fi

WORK_DIR="$(mktemp -d /tmp/cleanweb-local-dmg.XXXXXX)"
MOUNT_POINT="$(mktemp -d /tmp/cleanweb-local-dmg-mount.XXXXXX)"
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
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict --verbose=4 "$APP"
test -f "$APP/Contents/_CodeSignature/CodeResources"
"$(dirname "$0")/verify-macos-app-resources.sh" "$APP"

README="$STAGING/README-LOCAL-TESTING.txt"
cat > "$README" <<'TXT'
This is an ad-hoc signed local-testing build.

It is intended for developer testing only. It is not notarized and must not be
distributed as a production macOS release.
TXT

hdiutil create -volname CleanWeb -srcfolder "$STAGING" -ov -format UDZO "$OUTPUT" -quiet
xattr -cr "$OUTPUT"

echo "Wrote local-testing DMG: $OUTPUT"
