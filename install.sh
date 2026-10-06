#!/bin/sh
# Public bootstrap: installs only this release's reviewed source and an official
# checksum-verified runtime. Your gateway/account/folders are never embedded.
set -eu
umask 077
version='0.1.0-alpha.19'
repository='jianmosier/chat2local'
node_version='v24.21.0'
if [ "${1:-}" = '--help' ]; then
  echo 'chat2local: no arguments sets up your own private Cloudflare instance.'
  echo 'Use --instance HTTPS_ORIGIN to join an existing instance. Already connected computers open folder management.'
  exit 0
fi
if [ "$#" -ne 0 ] && { [ "$#" -ne 2 ] || [ "$1" != '--instance' ]; }; then echo 'Usage: install.sh [--instance HTTPS_ORIGIN]' >&2; exit 1; fi
if [ "$(id -u)" = 0 ]; then echo 'Run as your desktop user, without sudo/root.' >&2; exit 1; fi
case "$(uname -s)" in
  Darwin) os=darwin; base="$HOME/Library/Application Support/Chat2Local/bootstrap"; minimum='13.5'; actual=$(sw_vers -productVersion) ;;
  Linux) os=linux; base="${XDG_DATA_HOME:-$HOME/.local/share}/chat2local/bootstrap"; minimum='2.28'; actual=$(getconf GNU_LIBC_VERSION 2>/dev/null || true); case "$actual" in 'glibc '*) actual=${actual#glibc };; *) echo 'GNU/Linux with glibc is required; musl/Alpine is not supported.' >&2; exit 1;; esac ;;
  *) echo 'Use install.ps1 on Windows.' >&2; exit 1 ;;
esac
case "$(uname -m)" in arm64|aarch64) arch=arm64;; x86_64|amd64) arch=x64;; *) echo 'Unsupported CPU architecture.' >&2; exit 1;; esac
if [ "$os" = darwin ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then arch=arm64; fi
awk -v a="$actual" -v b="$minimum" 'BEGIN {if(a!~/^[0-9]+[.][0-9]+([.][0-9]+)*$/)exit 1;split(a,x,".");split(b,y,".");exit !(x[1]+0>y[1]+0 || (x[1]+0==y[1]+0&&x[2]+0>=y[2]+0))}' || { echo "Requires $os $minimum or newer." >&2; exit 1; }
for tool in curl tar awk; do command -v "$tool" >/dev/null 2>&1 || { echo "System tool missing: $tool" >&2; exit 1; }; done
if command -v shasum >/dev/null 2>&1; then checksum=shasum; elif command -v sha256sum >/dev/null 2>&1; then checksum=sha256sum; else echo 'A SHA-256 utility is required.' >&2; exit 1; fi
hash() { if [ "$checksum" = shasum ]; then shasum -a 256 "$1"; else sha256sum "$1"; fi; }
fetch() { curl --fail --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 5 --connect-timeout 20 --max-time 300 --max-filesize 150000000 "$1" --output "$2"; }
mkdir -p "$base"
[ ! -L "$base" ] || { echo 'Bootstrap location cannot be a symbolic link.' >&2; exit 1; }
lock="$base/.bootstrap-lock"
mkdir "$lock" 2>/dev/null || { echo 'Another bootstrap is running or an interrupted lock needs review. No process was stopped.' >&2; exit 1; }
stage=$(mktemp -d "$base/.download.XXXXXXXX")
stage=$(cd "$stage" && pwd -P)
trap 'rm -rf "$stage"; rmdir "$lock"' EXIT HUP INT TERM
runtime="node-$node_version-$os-$arch"
runtime_archive="$runtime.tar.gz"
echo "[chat2local $version] Preparing $os/$arch..."
fetch "https://nodejs.org/dist/$node_version/SHASUMS256.txt" "$stage/node-checksums"
expected=$(awk -v f="$runtime_archive" '$2==f {print $1}' "$stage/node-checksums")
case "$expected" in *[!0-9a-f]*|'') echo 'Official runtime checksum not found.' >&2; exit 1;; esac
[ "${#expected}" -eq 64 ] || exit 1
# Download and verify the archive even on retry; never trust a different global runtime.
fetch "https://nodejs.org/dist/$node_version/$runtime_archive" "$stage/node.tar.gz"
actual=$(hash "$stage/node.tar.gz"); [ "${actual%% *}" = "$expected" ] || { echo 'Runtime checksum mismatch.' >&2; exit 1; }
tar -xzf "$stage/node.tar.gz" -C "$stage"
node="$stage/$runtime/bin/node"
release="https://github.com/$repository/releases/download/v$version"
source="chat2local-source-v$version.tar.gz"
fetch "$release/$source.sha256" "$stage/source-checksum"
expected=$(awk 'NR==1 {print $1}' "$stage/source-checksum")
case "$expected" in *[!0-9a-f]*|'') echo 'Source checksum is invalid.' >&2; exit 1;; esac
[ "${#expected}" -eq 64 ] || exit 1
fetch "$release/$source" "$stage/source.tar.gz"
actual=$(hash "$stage/source.tar.gz"); [ "${actual%% *}" = "$expected" ] || { echo 'Source checksum mismatch.' >&2; exit 1; }
tar -tzf "$stage/source.tar.gz" | awk 'BEGIN{bad=0} !/^chat2local\// || /(^|\/)\.\.(\/|$)/ || /[\\]/ {bad=1} END{exit bad}' || { echo 'Unsafe source archive paths.' >&2; exit 1; }
tar -xzf "$stage/source.tar.gz" -C "$stage"
destination="$base/source-$version"
if [ -e "$destination" ]; then
  [ -d "$destination" ] && [ ! -L "$destination" ] || { echo 'Existing source location is unsafe.' >&2; exit 1; }
  "$node" "$stage/chat2local/scripts/check-source.mjs" "$destination" "$stage/chat2local/SOURCE-SHA256.json"
else
  mv "$stage/chat2local" "$destination"
fi
# The source persists; npm is used only for the owner's cloud setup. Runtime
# files remain private and are not copied from an existing computer.
export PATH="$stage/$runtime/bin:$PATH"
export CHAT2LOCAL_NPM_CLI="$stage/$runtime/lib/node_modules/npm/bin/npm-cli.js"
if [ ! -r /dev/tty ]; then echo 'Run in an interactive terminal to continue cloud authorization.' >&2; exit 1; fi
"$node" --use-env-proxy "$destination/scripts/setup-selfhost.mjs" "$@" < /dev/tty
