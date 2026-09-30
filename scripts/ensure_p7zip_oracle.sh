#!/usr/bin/env bash
set -euo pipefail

sha="${P7ZIP_ORACLE_SHA:-6819e2dc1917e1267babddc6391cea56ead7123d}"
repo="${P7ZIP_ORACLE_REPO:-https://github.com/p7zip-project/p7zip.git}"
dir="${P7ZIP_ORACLE_DIR:-/tmp/r7z-p7zip-compare}"

find_oracle_bin() {
  local make_dir="$1"
  local candidate
  for candidate in "$make_dir/_o/bin/7zz" "$make_dir/b/g/7zz" "$make_dir/_o/7zz"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  find "$make_dir" -type f -name 7zz -perm -111 | head -n 1
}

ensure_build_tools() {
  local tool
  for tool in make gcc g++ clang clang++ git cmake patchelf; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "$tool is required to build the p7zip oracle; run 'devenv shell' from the project root" >&2
      exit 127
    fi
  done
}

checkout_oracle_sha() {
  if ! git -C "$dir" cat-file -e "$sha^{commit}" 2>/dev/null; then
    git -C "$dir" fetch --tags origin >&2
  fi
  git -C "$dir" checkout --detach "$sha" >&2
}

use_existing_bin() {
  local make_dir="$1"
  local existing_bin
  if [[ "${R7Z_ORACLE_REBUILD:-0}" != 1 ]] && existing_bin="$(find_oracle_bin "$make_dir")" && [[ -n "$existing_bin" ]]; then
    "$existing_bin" i > "$dir/7zz-i.txt"
    printf '%s\n' "$existing_bin"
    exit 0
  fi
}

if [[ -d "$dir/.git" ]]; then
  current_sha="$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)"
  if [[ "$current_sha" == "$sha" ]]; then
    use_existing_bin "$dir/CPP/7zip/Bundles/Alone2"
  fi
fi

ensure_build_tools

if [[ -d "$dir/.git" ]]; then
  checkout_oracle_sha
else
  git clone "$repo" "$dir" >&2
  checkout_oracle_sha
fi

make_dir="$dir/CPP/7zip/Bundles/Alone2"
use_existing_bin "$make_dir"

export CMAKE_POLICY_VERSION_MINIMUM="${CMAKE_POLICY_VERSION_MINIMUM:-3.5}"
make -C "$make_dir" -f makefile.gcc >&2

bin="$(find_oracle_bin "$make_dir")"
if [[ -z "${bin:-}" || ! -x "$bin" ]]; then
  echo "built 7zz was not found under $make_dir" >&2
  exit 1
fi

"$bin" i > "$dir/7zz-i.txt"
printf '%s\n' "$bin"
