#!/usr/bin/env sh
# install.sh — yass installer for linux/macOS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/3rg0n/yass/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v0.1.0 --dir ~/bin
#
# Flags:
#   --version <tag>   pin a release tag (default: latest)
#   --dir <path>      install destination (default: /usr/local/bin or ~/.local/bin)
#   -h, --help        show this help

set -eu

REPO="3rg0n/yass"
VERSION=""
INSTALL_DIR=""

usage() {
  sed -n '2,12p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
    --dir)     [ $# -ge 2 ] || die "--dir needs a value";     INSTALL_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown flag: $1 (try --help)" ;;
  esac
done

# Required tools
for t in curl uname mktemp awk; do
  command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"
done

# OS / arch
case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *)      die "unsupported OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)   arch=amd64 ;;
  arm64|aarch64)  arch=arm64 ;;
  *)              die "unsupported arch: $(uname -m)" ;;
esac

# Resolve version
if [ -z "$VERSION" ]; then
  log "resolving latest release"
  VERSION=$(curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "https://api.github.com/repos/$REPO/releases/latest" \
    | awk -F'"' '/"tag_name":/ {print $4; exit}') || true
  [ -n "$VERSION" ] || die "could not resolve latest version (rate-limited? try --version vX.Y.Z)"
fi

# Resolve install dir
if [ -z "$INSTALL_DIR" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null || [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    INSTALL_DIR=/usr/local/bin
  else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi

binary="yass-${os}-${arch}"
base="https://github.com/$REPO/releases/download/$VERSION"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t yass-install)
trap 'rm -rf "$tmp"' EXIT INT TERM

log "downloading $binary $VERSION"
curl -fSL --progress-bar -o "$tmp/$binary" "$base/$binary"

log "verifying SHA-256"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
expected=$(awk -v b="$binary" '$2 ~ ("\\*?" b "$") {print $1; exit}' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "no SHA256SUMS entry for $binary"

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$binary" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$binary" | awk '{print $1}')
else
  die "neither sha256sum nor shasum available"
fi
[ "$actual" = "$expected" ] || die "checksum mismatch: got $actual, expected $expected"

dest="$INSTALL_DIR/yass"
chmod 0755 "$tmp/$binary"

if [ -w "$INSTALL_DIR" ]; then
  mv -f "$tmp/$binary" "$dest"
else
  log "needs sudo to write $INSTALL_DIR"
  sudo mv -f "$tmp/$binary" "$dest"
fi

# macOS: clear quarantine attribute when curl|sh path is used
if [ "$os" = "darwin" ] && command -v xattr >/dev/null 2>&1; then
  xattr -d com.apple.quarantine "$dest" 2>/dev/null || true
fi

log "installed yass $VERSION to $dest"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf 'note: %s is not on $PATH — add it to your shell profile.\n' "$INSTALL_DIR" ;;
esac

"$dest" --version
