#!/usr/bin/env bash
set -euo pipefail
# NDK and Go are installed by Android CI. Pin reviewed upstream source, never a Linux binary.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTPX_REV=f3ac850457129af3910cf641fe4e2bc2ee178172
: "${ANDROID_HOME:?Android SDK required}"
NDK="$ANDROID_HOME/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
git init -q "$WORK/httpx"
git -C "$WORK/httpx" remote add origin https://github.com/projectdiscovery/httpx.git
git -C "$WORK/httpx" fetch --depth 1 origin "$HTTPX_REV"
git -C "$WORK/httpx" checkout -q FETCH_HEAD
python3 "$ROOT/native-tools/prepare-httpx.py" "$WORK/httpx"
cd "$WORK/httpx"
gofmt -w common/httpx/httpx.go
# Exercise the actual patched CLI before cross-compiling the same source.
go build -trimpath -buildvcs=false -o "$WORK/httpx-host" ./cmd/httpx
python3 "$ROOT/tests/test-httpx-runtime.py" "$WORK/httpx-host"
export GOOS=android GOARCH=arm64 CGO_ENABLED=1
export CC="$NDK/aarch64-linux-android26-clang"
export CXX="$NDK/aarch64-linux-android26-clang++"
TARGET="$ROOT/app/src/main/jniLibs/arm64-v8a/libhttpx.so"
mkdir -p "$(dirname "$TARGET")"
go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$TARGET" ./cmd/httpx
readelf -h "$TARGET" | grep -q 'AArch64'
readelf -l "$TARGET" | grep -q '/system/bin/linker64'
echo "Built Android ARM64 HTTPX from $HTTPX_REV (strict TLS patch)"
