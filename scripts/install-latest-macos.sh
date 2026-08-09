#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${CLEANWEB_GITHUB_REPOSITORY:-yangsx95/clean-web}"
WORKFLOW="${CLEANWEB_GITHUB_WORKFLOW:-build.yml}"
APPLICATION_PATH="/Applications/CleanWeb.app"
DRY_RUN=false
REQUESTED_RUN_ID=""

usage() {
  cat <<'TXT'
Usage: scripts/install-latest-macos.sh [--dry-run] [--run-id ID]

Downloads the newest successful CleanWeb macOS artifact from GitHub Actions,
installs it into /Applications, and starts the installed copy.

Options:
  --dry-run    Resolve and display the build without downloading or installing.
  --run-id ID  Install a specific successful GitHub Actions run.
  -h, --help   Show this help.
TXT
}

while (($# > 0)); do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --run-id)
      [[ $# -ge 2 ]] || { echo "--run-id requires a value" >&2; exit 2; }
      REQUESTED_RUN_ID="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || { echo "This installer only supports macOS." >&2; exit 1; }
command -v gh >/dev/null || { echo "GitHub CLI is required: brew install gh" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required: brew install jq" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Sign in first: gh auth login" >&2; exit 1; }

retry() {
  attempts="$1"
  shift
  attempt=1
  while true; do
    if "$@"; then
      return 0
    fi
    status=$?
    if [[ "$attempt" -ge "$attempts" ]]; then
      return "$status"
    fi
    echo "Command failed; retrying ($attempt/$attempts)..." >&2
    sleep $((attempt * 2))
    attempt=$((attempt + 1))
  done
}

case "$(uname -m)" in
  arm64) ARTIFACT_NAME="cleanweb-macos-arm64" ;;
  x86_64) ARTIFACT_NAME="cleanweb-macos-x64" ;;
  *) echo "Unsupported Mac architecture: $(uname -m)" >&2; exit 1 ;;
esac

resolve_run() {
  if [[ -n "$REQUESTED_RUN_ID" ]]; then
    gh run view "$REQUESTED_RUN_ID" --repo "$REPOSITORY" \
      --json databaseId,headSha,conclusion,status,url
    return
  fi
  gh run list --repo "$REPOSITORY" --workflow "$WORKFLOW" --branch main \
    --status success --limit 20 \
    --json databaseId,headSha,conclusion,status,url \
    --jq '.[0]'
}

RUN_JSON="$(retry 3 resolve_run)"
RUN_ID="$(printf '%s' "$RUN_JSON" | jq -r '.databaseId // empty')"
RUN_SHA="$(printf '%s' "$RUN_JSON" | jq -r '.headSha // empty')"
RUN_URL="$(printf '%s' "$RUN_JSON" | jq -r '.url // empty')"
RUN_STATUS="$(printf '%s' "$RUN_JSON" | jq -r '.status // empty')"
RUN_CONCLUSION="$(printf '%s' "$RUN_JSON" | jq -r '.conclusion // empty')"

[[ -n "$RUN_ID" ]] || { echo "No successful $WORKFLOW run was found on main." >&2; exit 1; }
[[ "$RUN_STATUS" == "completed" && "$RUN_CONCLUSION" == "success" ]] || {
  echo "Run $RUN_ID is not a completed successful build." >&2
  exit 1
}

ARTIFACT_COUNT="$(retry 3 gh api "repos/$REPOSITORY/actions/runs/$RUN_ID/artifacts" \
  --jq "[.artifacts[] | select(.name == \"$ARTIFACT_NAME\" and (.expired | not))] | length")"
[[ "$ARTIFACT_COUNT" == "1" ]] || {
  echo "Run $RUN_ID does not contain one unexpired $ARTIFACT_NAME artifact." >&2
  exit 1
}

echo "CleanWeb latest macOS build"
echo "  Run:      $RUN_ID"
echo "  Commit:   ${RUN_SHA:0:12}"
echo "  Artifact: $ARTIFACT_NAME"
echo "  URL:      $RUN_URL"

if [[ "$DRY_RUN" == "true" ]]; then
  exit 0
fi

WORK_DIR="$(mktemp -d /private/tmp/cleanweb-latest-installer.XXXXXX)"
MOUNT_POINT="$WORK_DIR/mount"
DOWNLOAD_DIR="$WORK_DIR/download"
STAGED_APP="$WORK_DIR/CleanWeb.app"
INSTALL_STAGE="/Applications/.CleanWeb.app.install.$$"
BACKUP_APP="/Applications/.CleanWeb.app.backup.$$"
MOUNT_ATTACHED=false
INSTALL_SUCCEEDED=false

cleanup() {
  if [[ "$MOUNT_ATTACHED" == "true" ]]; then
    hdiutil detach "$MOUNT_POINT" -quiet >/dev/null 2>&1 || true
  fi
  if [[ -e "$INSTALL_STAGE" ]]; then
    rm -rf "$INSTALL_STAGE"
  fi
  if [[ "$INSTALL_SUCCEEDED" == "true" && -e "$BACKUP_APP" ]]; then
    rm -rf "$BACKUP_APP"
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$DOWNLOAD_DIR" "$MOUNT_POINT"
echo "Downloading artifact..."
retry 3 gh run download "$RUN_ID" --repo "$REPOSITORY" --name "$ARTIFACT_NAME" --dir "$DOWNLOAD_DIR"

DMG_COUNT="$(find "$DOWNLOAD_DIR" -type f -name '*.dmg' | wc -l | tr -d ' ')"
[[ "$DMG_COUNT" == "1" ]] || {
  echo "Expected exactly one DMG in $ARTIFACT_NAME, found $DMG_COUNT." >&2
  exit 1
}
DMG_FILE="$(find "$DOWNLOAD_DIR" -type f -name '*.dmg' -print -quit)"

echo "Mounting and validating DMG..."
hdiutil attach "$DMG_FILE" -nobrowse -readonly -mountpoint "$MOUNT_POINT" -quiet
MOUNT_ATTACHED=true
SOURCE_APP="$MOUNT_POINT/CleanWeb.app"
[[ -d "$SOURCE_APP" ]] || { echo "CleanWeb.app is missing from the DMG." >&2; exit 1; }
ditto "$SOURCE_APP" "$STAGED_APP"
hdiutil detach "$MOUNT_POINT" -quiet
MOUNT_ATTACHED=false

BUNDLE_ID="$(defaults read "$STAGED_APP/Contents/Info" CFBundleIdentifier 2>/dev/null || true)"
[[ "$BUNDLE_ID" == "app.cleanweb.desktop" ]] || {
  echo "Unexpected bundle identifier: $BUNDLE_ID" >&2
  exit 1
}
codesign --verify --deep --strict "$STAGED_APP"
ARCHS="$(lipo -archs "$STAGED_APP/Contents/MacOS/cleanweb")"
EXPECTED_ARCH="$(uname -m)"
[[ " $ARCHS " == *" $EXPECTED_ARCH "* ]] || {
  echo "Downloaded app architecture '$ARCHS' does not include '$EXPECTED_ARCH'." >&2
  exit 1
}

VERSION="$(defaults read "$STAGED_APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo unknown)"
echo "Validated CleanWeb $VERSION ($ARCHS)."

echo "Closing running CleanWeb copies..."
while IFS= read -r pid; do
  [[ -n "$pid" ]] || continue
  executable="$(lsof -a -p "$pid" -d txt -Fn 2>/dev/null | sed -n 's/^n//p' | head -1)"
  if [[ "$executable" == *"/CleanWeb.app/Contents/MacOS/cleanweb" ]]; then
    kill -TERM "$pid" 2>/dev/null || true
  fi
done < <(pgrep -x cleanweb || true)

for _ in {1..10}; do
  if ! pgrep -x cleanweb >/dev/null; then
    break
  fi
  sleep 1
done

echo "Installing into /Applications..."
ditto "$STAGED_APP" "$INSTALL_STAGE"
if [[ -e "$APPLICATION_PATH" ]]; then
  mv "$APPLICATION_PATH" "$BACKUP_APP"
fi
if ! mv "$INSTALL_STAGE" "$APPLICATION_PATH"; then
  if [[ -e "$BACKUP_APP" && ! -e "$APPLICATION_PATH" ]]; then
    mv "$BACKUP_APP" "$APPLICATION_PATH"
  fi
  echo "Installation failed while replacing $APPLICATION_PATH." >&2
  exit 1
fi

if ! open -na "$APPLICATION_PATH"; then
  rm -rf "$APPLICATION_PATH"
  if [[ -e "$BACKUP_APP" ]]; then
    mv "$BACKUP_APP" "$APPLICATION_PATH"
    open -na "$APPLICATION_PATH" || true
  fi
  echo "The new app failed to launch; the previous app was restored." >&2
  exit 1
fi

for _ in {1..15}; do
  if pgrep -x cleanweb >/dev/null; then
    INSTALL_SUCCEEDED=true
    break
  fi
  sleep 1
done

if [[ "$INSTALL_SUCCEEDED" != "true" ]]; then
  rm -rf "$APPLICATION_PATH"
  if [[ -e "$BACKUP_APP" ]]; then
    mv "$BACKUP_APP" "$APPLICATION_PATH"
    open -na "$APPLICATION_PATH" || true
  fi
  echo "The new app exited during startup; the previous app was restored." >&2
  exit 1
fi

echo "Installed and started CleanWeb $VERSION from commit ${RUN_SHA:0:12}."
