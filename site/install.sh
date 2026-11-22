#!/bin/sh
# Install asiri, then add it to Rex's command palette.
# curl -fsSL https://asiri.run/install.sh | sh
# Later: asiri update. Pick a version with ASIRI_VERSION=v0.1.0.
set -eu

repo="gingered-cat/asiri"
version="${ASIRI_VERSION:-}"
dest="${HOME}/.local/bin"
bin="${dest}/asiri"

say() { printf 'asiri: %s\n' "$*"; }
die() { say "$*" >&2; exit 1; }

os=$(uname -s)
case "$os" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) die "$os is not supported. Use macOS or Linux." ;;
esac

arch=$(uname -m)
case "$arch" in
  arm64|aarch64) arch=arm64 ;;
  x86_64|amd64) arch=amd64 ;;
  *) die "$arch is not supported." ;;
esac

if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" |
    sed -n 's/.*"tag_name": *"\(v[0-9][0-9.]*\)".*/\1/p' | head -n 1) || true
  [ -n "$version" ] || die "couldn't find the latest release; set ASIRI_VERSION=v0.1.0 to pick one"
fi
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "version ${version}: want a tag like v0.1.0" ;;
esac

name="asiri-${version}-${os}-${arch}"
base="https://github.com/${repo}/releases/download/${version}"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

sums=$(curl -fsSL "${base}/checksums.txt") || die "couldn't download checksums for ${version}; is ${version} a released version? https://github.com/${repo}/releases"

# checksum NAME: the published SHA-256 of a release file, matched by its exact
# base name (v0.1.0 listed paths like ./darwin-arm64/asiri-...).
checksum() {
  printf '%s\n' "$sums" | awk -v name="$1" '{ f = $2; sub(/^\*/, "", f); n = split(f, p, "/"); if (p[n] == name) { print $1; exit } }'
}

# install_file NAME TARGET: download a release file, verify it, move it into place.
install_file() {
  want=$(checksum "$1")
  [ -n "$want" ] || die "no checksum for $1"
  say "downloading $1"
  curl -fsSL "${base}/$1" -o "$tmp" || die "couldn't download $1"
  if command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$tmp" | awk '{print $1}')
  else
    got=$(sha256sum "$tmp" | awk '{print $1}')
  fi
  [ "$got" = "$want" ] || die "checksum mismatch for $1"
  chmod 755 "$tmp"
  mv "$tmp" "$2"
  say "installed $2"
}

mkdir -p "$dest"
install_file "$name" "$bin"

# macOS: the Touch ID helper that signs approvals (releases from v0.2.0).
helper="asiri-touchid-${version}-darwin-${arch}"
if [ "$os" = darwin ] && [ -n "$(checksum "$helper")" ]; then
  install_file "$helper" "${dest}/asiri-touchid"
fi
trap - EXIT

case ":${PATH}:" in
  *":${dest}:"*) ;;
  *) say "add ${dest} to PATH, then open a new terminal" ;;
esac

if ! command -v rex >/dev/null 2>&1; then
  say "Rex is not installed, so the palette plugin was not added."
  say "Install Rex, pair a vault, then run: asiri rex install"
  exit 0
fi

if ! "$bin" status >/dev/null 2>&1; then
  say "no paired owner profile yet. Pair the vault, then run: asiri rex install"
  exit 0
fi

say "adding asiri to Rex"
"$bin" rex install
if [ "$os" = darwin ] && [ -x "${dest}/asiri-touchid" ]; then
  say "to make approvals need Touch ID, run: asiri touchid enroll"
fi
