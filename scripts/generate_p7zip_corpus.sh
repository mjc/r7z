#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="$root/tests/corpus/7z/generated"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [[ -n "${P7ZIP_BIN:-}" ]]; then
  sevenz="$P7ZIP_BIN"
else
  sevenz="$("$root/scripts/ensure_p7zip_oracle.sh")"
fi

rm -rf "$out_dir"
mkdir -p "$out_dir"

mkdir -p "$tmp/input/nested"
printf 'alpha\n' > "$tmp/input/alpha.txt"
printf 'bravo\n' > "$tmp/input/nested/bravo.txt"
perl -e '
  my ($path) = @ARGV;
  my $data = "\x90" x 4096;
  for (my $pos = 32; $pos < 4000; $pos += 97) {
    substr($data, $pos, 1) = ($pos % 2 == 0) ? "\xE8" : "\xE9";
    my $target = ($pos * 13) & 0xFFFFFFFF;
    substr($data, $pos + 1, 4) = pack("V", $target);
  }
  open my $fh, ">:raw", $path or die "open $path: $!";
  print {$fh} $data;
' "$tmp/input/prog.bin"
find "$tmp/input" -exec touch -t 202401020304.05 {} +

run_7z() {
  "$sevenz" "$@" >/dev/null
}

run_7z a "$out_dir/copy_nonsolid.7z" \
  "$tmp/input/alpha.txt" "$tmp/input/nested" \
  -m0=Copy -ms=off -mmt=off

run_7z a "$out_dir/lzma_solid.7z" \
  "$tmp/input/alpha.txt" "$tmp/input/nested" \
  -m0=LZMA -ms=on -mmt=off

run_7z a "$out_dir/lzma2_nonsolid.7z" \
  "$tmp/input/alpha.txt" "$tmp/input/nested" \
  -m0=LZMA2 -ms=off -mmt=off

run_7z a "$out_dir/deflate_nonsolid.7z" \
  "$tmp/input/alpha.txt" "$tmp/input/nested" \
  -m0=Deflate -ms=off -mmt=off

run_7z a "$out_dir/deflate64_nonsolid.7z" \
  "$tmp/input/alpha.txt" "$tmp/input/nested" \
  -m0=Deflate64 -ms=off -mmt=off

run_7z a "$out_dir/delta_lzma2.7z" \
  "$tmp/input/alpha.txt" "$tmp/input/nested" \
  -m0=Delta -m1=LZMA2 -ms=off -mmt=off

run_7z a "$out_dir/bcj_lzma2.7z" \
  "$tmp/input/prog.bin" \
  -m0=BCJ -m1=LZMA2 -mmt=off

run_7z a "$out_dir/aes_header.7z" \
  "$tmp/input/alpha.txt" \
  -m0=LZMA2 -pCorpusSecret -mhe=on -mmt=off

run_7z a "$out_dir/split.7z" \
  "$tmp/input/alpha.txt" "$tmp/input/nested/bravo.txt" \
  -m0=Copy -v128b -mmt=off
rm -f "$out_dir/split.7z"

run_7z a "$out_dir/bzip2_nonsolid.7z" \
  "$tmp/input/alpha.txt" \
  -m0=BZip2 -mmt=off

printf 'generated corpus with %s\n' "$sevenz"
