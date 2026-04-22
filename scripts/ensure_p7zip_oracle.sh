#!/usr/bin/env bash
set -euo pipefail

sha="${P7ZIP_ORACLE_SHA:-6819e2dc1917e1267babddc6391cea56ead7123d}"
repo="${P7ZIP_ORACLE_REPO:-https://github.com/p7zip-project/p7zip.git}"
dir="${P7ZIP_ORACLE_DIR:-/tmp/r7z-p7zip-compare}"
script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

if ! command -v make >/dev/null 2>&1; then
  if command -v nix-shell >/dev/null 2>&1 && [[ "${R7Z_ORACLE_IN_NIX:-0}" != 1 ]]; then
    export P7ZIP_ORACLE_SHA="$sha" P7ZIP_ORACLE_REPO="$repo" P7ZIP_ORACLE_DIR="$dir"
    exec nix-shell -p gnumake gcc git cmake --run "R7Z_ORACLE_IN_NIX=1 bash '$script'"
  fi
  echo "make is required to build the p7zip oracle" >&2
  exit 127
fi

if [[ ! -d "$dir/.git" ]]; then
  git clone "$repo" "$dir" >&2
fi

git -C "$dir" fetch --tags origin >&2
git -C "$dir" checkout --detach "$sha" >&2

make_dir="$dir/CPP/7zip/Bundles/Alone2"
existing_bin="$make_dir/_o/bin/7zz"
if [[ "${R7Z_ORACLE_REBUILD:-0}" != 1 && -x "$existing_bin" ]]; then
  "$existing_bin" i > "$dir/7zz-i.txt"
  printf '%s\n' "$existing_bin"
  exit 0
fi

export CMAKE_POLICY_VERSION_MINIMUM="${CMAKE_POLICY_VERSION_MINIMUM:-3.5}"
make -C "$make_dir" -f makefile.gcc >&2

bin="$make_dir/b/g/7zz"
if [[ ! -x "$bin" ]]; then
  bin="$make_dir/_o/7zz"
fi
if [[ ! -x "$bin" ]]; then
  bin="$(find "$make_dir" -type f -name 7zz -perm -111 | head -n 1)"
fi
if [[ -z "${bin:-}" || ! -x "$bin" ]]; then
  echo "built 7zz was not found under $make_dir" >&2
  exit 1
fi

"$bin" i > "$dir/7zz-i.txt"
printf '%s\n' "$bin"
