#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${RUNNER_TEMP:-/tmp}/droidmap-nmap"
NMAP_COMMIT="79a86bb1c0f4272c6bf12c870adb6524c26e0eb0"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to Android NDK r27+}"
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
export PATH="$TOOLCHAIN/bin:$PATH"
export CC=aarch64-linux-android24-clang CXX=aarch64-linux-android24-clang++ AR=llvm-ar RANLIB=llvm-ranlib

rm -rf "$WORK"
git clone --filter=blob:none https://github.com/mr8391/nmap-android.git "$WORK"
git -C "$WORK" checkout --detach "$NMAP_COMMIT"

cmake -S "$WORK/boringssl" -B "$WORK/boringssl/build" \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF -DCMAKE_CXX_STANDARD=17
cmake --build "$WORK/boringssl/build" --target ssl crypto -j2
mkdir -p "$WORK/boringssl/lib"
cp "$(find "$WORK/boringssl/build" -name libssl.a -print -quit)" "$WORK/boringssl/lib/libssl.a"
cp "$(find "$WORK/boringssl/build" -name libcrypto.a -print -quit)" "$WORK/boringssl/lib/libcrypto.a"

(cd "$WORK/libpcap" && ./configure --host=aarch64-linux-android CC="$CC" AR="$AR" RANLIB="$RANLIB" --without-libnl && make -j2)
(cd "$WORK/libpcre" && ./configure --host=aarch64-linux-android CC="$CC" AR="$AR" RANLIB="$RANLIB" --disable-shared --enable-static && make -j2)

cd "$WORK"
export CPPFLAGS="-I$WORK/libpcap -I$WORK/libpcre/src -I$WORK/boringssl/include"
export LDFLAGS="-L$WORK/libpcap -L$WORK/libpcre/.libs -L$WORK/boringssl/lib"
./configure --host=aarch64-linux-android --with-libpcap=included --with-libpcre=included \
  --with-openssl="$WORK/boringssl" --disable-zenmap --disable-nmap-update --without-liblua --without-libssh2 \
  CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" CPPFLAGS="$CPPFLAGS" LDFLAGS="$LDFLAGS" \
  ac_cv_lib_crypto_BIO_int_ctrl=yes ac_cv_lib_ssl_SSL_new=yes ac_cv_func_EVP_sha256=yes
make -j2 nmap

test -x "$WORK/nmap"
JNI="$ROOT/app/src/main/jniLibs/arm64-v8a"
DATA="$ROOT/app/src/main/assets/nmap-data"
mkdir -p "$JNI" "$DATA"
cp "$WORK/nmap" "$JNI/libnmap.so"
cp "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so" "$JNI/libc++_shared.so"
for f in nmap-service-probes nmap-services nmap-protocols nmap-rpc; do test -s "$WORK/$f"; cp "$WORK/$f" "$DATA/$f"; done
