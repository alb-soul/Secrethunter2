#!/usr/bin/env bash
# bench.sh — bandingkan satu/lebih binary secrethunter2 pada corpus gencorpus.
#
#   tools/bench.sh <corpus.jsonl> <binary> [binary...]
#
# Untuk tiap binary: jalankan mode kontrak (`--httpx-json … --scope target.test
# -o … -t 8 -silent`) dalam mode teks DAN --json, catat waktu + RSS puncak,
# lalu nilai hasilnya dengan tools/benchcmp.
set -euo pipefail
corpus="$1"; shift
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d /tmp/sh2bench.XXXXXX)"
( cd "$here/.." && go build -o "$work/benchcmp" ./tools/benchcmp )
threads="${THREADS:-8}"

for bin in "$@"; do
    name="$(basename "$bin")"
    echo "════ $name ════"
    tfile="$work/$name.txt"; jfile="$work/$name.json"
    if command -v /usr/bin/time >/dev/null 2>&1; then
        /usr/bin/time -f "text  : %e s wall, %M KB maxRSS, exit %x" \
            "$bin" --httpx-json "$corpus" --scope target.test -o "$tfile" -t "$threads" -silent >/dev/null || true
        /usr/bin/time -f "json  : %e s wall, %M KB maxRSS, exit %x" \
            "$bin" --httpx-json "$corpus" --scope target.test -o "$jfile" -t "$threads" -silent --json >/dev/null || true
    else
        s=$(date +%s.%N)
        "$bin" --httpx-json "$corpus" --scope target.test -o "$tfile" -t "$threads" -silent >/dev/null; rc=$?
        echo "text  : $(echo "$(date +%s.%N) - $s" | bc) s wall, exit $rc"
        "$bin" --httpx-json "$corpus" --scope target.test -o "$jfile" -t "$threads" -silent --json >/dev/null || true
    fi
    "$work/benchcmp" -truth "$corpus.truth.tsv" -findings "$jfile" -text "$tfile" ${VERBOSE:+-v}
done
echo "(artefak: $work)"
