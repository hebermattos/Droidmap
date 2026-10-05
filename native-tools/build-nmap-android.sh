#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${RUNNER_TEMP:-/tmp}/droidmap-nmap"
NMAP_COMMIT="79a86bb1c0f4272c6bf12c870adb6524c26e0eb0"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to Android NDK r27+}"

rm -rf "$WORK"
git clone --filter=blob:none https://github.com/mr8391/nmap-android.git "$WORK"
git -C "$WORK" checkout --detach "$NMAP_COMMIT"
export NDK_HOME="$ANDROID_NDK_HOME"
export ANDROID_NDK_HOME
(cd "$WORK" && chmod +x build-android.sh && ./build-android.sh)

test -x "$WORK/nmap"
JNI="$ROOT/app/src/main/jniLibs/arm64-v8a"
DATA="$ROOT/app/src/main/assets/nmap-data"
mkdir -p "$JNI" "$DATA"
cp "$WORK/nmap" "$JNI/libnmap.so"
cp "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so" "$JNI/libc++_shared.so"
for f in nmap-service-probes nmap-services nmap-protocols nmap-rpc; do
  test -s "$WORK/$f"
  cp "$WORK/$f" "$DATA/$f"
done
