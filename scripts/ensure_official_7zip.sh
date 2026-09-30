#!/usr/bin/env bash
set -euo pipefail

version=26.03
archive="7z2603-linux-x64.tar.xz"
sha256="dc99eff5008f1ab79bd7084c68513701547a808a89502bf4133683535ab3c695"
root="${OFFICIAL_7ZIP_DIR:-target/official-7zip-${version}}"
url="https://www.7-zip.org/a/${archive}"

mkdir -p "$root"
if [[ ! -x "$root/7zz" ]]; then
  command -v curl >/dev/null || { echo "curl is required to download official 7-Zip" >&2; exit 127; }
  command -v sha256sum >/dev/null || { echo "sha256sum is required to verify official 7-Zip" >&2; exit 127; }
  command -v tar >/dev/null || { echo "tar is required to unpack official 7-Zip" >&2; exit 127; }
  curl --fail --location --retry 2 "$url" --output "$root/$archive"
  printf '%s  %s\n' "$sha256" "$root/$archive" | sha256sum --check --status || {
    echo "official 7-Zip archive checksum mismatch" >&2
    exit 1
  }
  tar -xJf "$root/$archive" -C "$root"
fi

printf '%s\n' "$root/7zz"
