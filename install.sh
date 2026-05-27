#!/usr/bin/env sh
# install.sh — yass installer for linux/macOS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/cisco-sbg-emu/yass/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v0.1.0 --dir ~/bin
#
# Defaults: install latest tag to /usr/local/bin (sudo if needed) or
# ~/.local/bin if /usr/local/bin isn't writable. Verifies sha256 against
# the release's SHA256SUMS.

set -eu

REPO="cisco-sbg-emu/yass"
VERSION=""
INSTALL_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dir)     INSTALL_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

uname_s=$(uname -s)
case "$uname_s" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) echo "unsupported OS: $uname_s" >&2; exit 1 ;;
esac

uname_m=$(uname -m)
case "$uname_m" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported arch: $uname_m" >&2; exit 1 ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
need curl
need uname

if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || { echo "could not resolve latest version (private repo? try --version)" >&2; exit 1; }
fi

if [ -z "$INSTALL_DIR" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    INSTALL_DIR=/usr/local/bin
  elif [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR=/usr/local/bin
  else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi

binary="yass-${os}-${arch}"
url="https://github.com/$REPO/releases/download/$VERSION/$binary"
sums_url="https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "==> downloading $binary $VERSION"
curl -fSL --progress-bar -o "$tmp/$binary" "$url"

echo "==> verifying SHA-256"
curl -fsSL -o "$tmp/SHA256SUMS" "$sums_url"
expected=$(grep " \*\?$binary\$" "$tmp/SHA256SUMS" | awk '{print $1}')
[ -n "$expected" ] || { echo "no SHA256SUMS entry for $binary" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$binary" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$binary" | awk '{print $1}')
else
  echo "no sha256sum or shasum available" >&2; exit 1
fi
[ "$actual" = "$expected" ] || { echo "checksum mismatch: $actual != $expected" >&2; exit 1; }

dest="$INSTALL_DIR/yass"
chmod +x "$tmp/$binary"
if [ -w "$INSTALL_DIR" ]; then
  mv "$tmp/$binary" "$dest"
else
  echo "==> needs sudo to write $INSTALL_DIR"
  sudo mv "$tmp/$binary" "$dest"
fi

echo "==> installed yass $VERSION to $dest"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "note: $INSTALL_DIR is not on \$PATH — add it to your shell profile" ;;
esac
"$dest" --version
