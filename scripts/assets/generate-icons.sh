#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_ICON="$ROOT_DIR/assets/app-icon.svg"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -r "$TMP_DIR"
}
trap cleanup EXIT

if [ ! -f "$SOURCE_ICON" ]; then
  echo "Missing source icon: $SOURCE_ICON" >&2
  exit 1
fi

npx tauri icon "$SOURCE_ICON" --output "$TMP_DIR"

mkdir -p "$ROOT_DIR/apps/desktop/src-tauri/icons"
find "$ROOT_DIR/apps/desktop/src-tauri/icons" -maxdepth 1 -type f \( -name "*.png" -o -name "*.ico" -o -name "*.icns" \) -delete
cp "$TMP_DIR"/32x32.png "$ROOT_DIR/apps/desktop/src-tauri/icons/32x32.png"
cp "$TMP_DIR"/64x64.png "$ROOT_DIR/apps/desktop/src-tauri/icons/64x64.png"
cp "$TMP_DIR"/128x128.png "$ROOT_DIR/apps/desktop/src-tauri/icons/128x128.png"
cp "$TMP_DIR"/128x128@2x.png "$ROOT_DIR/apps/desktop/src-tauri/icons/128x128@2x.png"
cp "$TMP_DIR"/icon.png "$ROOT_DIR/apps/desktop/src-tauri/icons/icon.png"
cp "$TMP_DIR"/icon.icns "$ROOT_DIR/apps/desktop/src-tauri/icons/icon.icns"
cp "$TMP_DIR"/icon.ico "$ROOT_DIR/apps/desktop/src-tauri/icons/icon.ico"
cp "$TMP_DIR"/Square*Logo.png "$ROOT_DIR/apps/desktop/src-tauri/icons/"
cp "$TMP_DIR"/StoreLogo.png "$ROOT_DIR/apps/desktop/src-tauri/icons/StoreLogo.png"

mkdir -p "$ROOT_DIR/website/assets"
cp "$SOURCE_ICON" "$ROOT_DIR/website/assets/favicon.svg"

ANDROID_RES_DIR="$ROOT_DIR/apps/mobile/src-tauri/gen/android/app/src/main/res"
if [ -d "$ANDROID_RES_DIR" ]; then
  mkdir -p "$ANDROID_RES_DIR"/mipmap-anydpi-v26 "$ANDROID_RES_DIR"/values
  find "$ANDROID_RES_DIR" -maxdepth 1 -type d -name "mipmap-*" -exec rm -r {} +
  [ ! -f "$ANDROID_RES_DIR/drawable/ic_launcher_background.xml" ] || rm "$ANDROID_RES_DIR/drawable/ic_launcher_background.xml"
  [ ! -f "$ANDROID_RES_DIR/drawable-v24/ic_launcher_foreground.xml" ] || rm "$ANDROID_RES_DIR/drawable-v24/ic_launcher_foreground.xml"
  mkdir -p "$ANDROID_RES_DIR"/mipmap-anydpi-v26 "$ANDROID_RES_DIR"/values
  cp -R "$TMP_DIR"/android/mipmap-* "$ANDROID_RES_DIR"/
  cp "$TMP_DIR"/android/values/ic_launcher_background.xml "$ANDROID_RES_DIR/values/ic_launcher_background.xml"
fi

IOS_APPICON_DIR="$ROOT_DIR/apps/mobile/src-tauri/gen/apple/Assets.xcassets/AppIcon.appiconset"
if [ -d "$IOS_APPICON_DIR" ]; then
  cp "$TMP_DIR"/ios/*.png "$IOS_APPICON_DIR"/
fi

echo "Generated app icons from assets/app-icon.svg"
