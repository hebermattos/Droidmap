#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${RUNNER_TEMP:-/tmp}/droidmap-nmap"
ARCHIVE="$WORK/nmap.tar.bz2"
URL="https://github.com/kost/nmap-android/releases/download/v7.31/nmap-7.31-android-aarch64-bin.tar.bz2"
SHA256="eb454cab7eff6296e9b0b3f60806ec732f85cdfc1634c731afeb9674e136cc00"

rm -rf "$WORK"
mkdir -p "$WORK"
curl --fail --location --retry 3 --output "$ARCHIVE" "$URL"
echo "$SHA256  $ARCHIVE" | sha256sum --check -
tar -xjf "$ARCHIVE" -C "$WORK"

SOURCE="$WORK/nmap-7.31"
test -x "$SOURCE/bin/nmap"
JNI="$ROOT/app/src/main/jniLibs/arm64-v8a"
DATA="$ROOT/app/src/main/assets/nmap-data"
mkdir -p "$JNI" "$DATA"
cp "$SOURCE/bin/nmap" "$JNI/libnmap.so"
for f in nmap-service-probes nmap-services nmap-protocols nmap-rpc; do
  test -s "$SOURCE/share/nmap/$f"
  cp "$SOURCE/share/nmap/$f" "$DATA/$f"
done
rm -rf "$DATA/scripts" "$DATA/nselib"
cp -R "$SOURCE/share/nmap/scripts" "$DATA/scripts"
cp -R "$SOURCE/share/nmap/nselib" "$DATA/nselib"
(cd "$DATA" && find scripts nselib -type f -print | LC_ALL=C sort > nse-files.txt)
test -s "$DATA/scripts/script.db"
test -s "$DATA/nse-files.txt"
