#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${R7Z_COMMONS_COMPRESS_CORPUS_DIR:-$root/target/corpus/7z/apache-commons-compress}"
base_url="${R7Z_COMMONS_COMPRESS_RAW_URL:-https://raw.githubusercontent.com/apache/commons-compress/master/src/test/resources}"
manifest="$out_dir/manifest.tsv"

files=(
  "7z-empty-mhc-off.7z"
  "7z-hello-mhc-off-copy.7z"
  "7z-hello-mhc-off-lzma2.7z"
  "COMPRESS-256.7z"
  "COMPRESS-348.7z"
  "COMPRESS-492.7z"
  "COMPRESS-592.7z"
  "COMPRESS-681.7z"
  "bla.7z"
  "bla-nonames.7z"
  "bla.deflate.7z"
  "bla.deflate64.7z"
  "bla.encrypted.7z"
  "bla-multi.7z.001"
  "bla-multi.7z.002"
)

mkdir -p "$out_dir"

for file in "${files[@]}"; do
  curl -fsSL "$base_url/$file" -o "$out_dir/$file"
done

{
  printf '# archive_path\tpassword_or_-\texpectation\texpected_file_count\n'
  for file in "${files[@]}"; do
    case "$file" in
      *.002) ;;
      bla.encrypted.7z)
        printf '%s\t%s\t%s\t%s\n' "$out_dir/$file" "-" "password_required" "-"
        ;;
      COMPRESS-681.7z|bla.deflate.7z)
        printf '%s\t%s\t%s\t%s\n' "$out_dir/$file" "-" "extract" "-"
        ;;
      *)
        printf '%s\t%s\t%s\t%s\n' "$out_dir/$file" "-" "open" "-"
        ;;
    esac
  done
} > "$manifest"

printf '%s\n' "$manifest"
