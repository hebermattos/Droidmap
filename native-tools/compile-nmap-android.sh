#!/usr/bin/env bash
set -euo pipefail
# Build a standalone Android runtime. The APK packaging script remains independent.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to Android NDK 27.2.12479018}"
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
test -x "$NDK_BIN/aarch64-linux-android26-clang"
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018[[:space:]]*$' "$ANDROID_NDK_HOME/source.properties"
NMAP_VERSION=7.992
NMAP_SHA256=0c12660eddbf7eabeff6996cb0c044a4eadf2bb0c6fbcb340d6cf72b1caee402
OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
OUTPUT="${NMAP_OUTPUT_DIR:-$ROOT/dist/nmap-android-arm64}"
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/droidmap-nmap-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
JOBS="${NMAP_BUILD_JOBS:-$(nproc)}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid NMAP_BUILD_JOBS' >&2; exit 1; }
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export PATH="$NDK_BIN:$PATH"
export CC=aarch64-linux-android26-clang CXX=aarch64-linux-android26-clang++
export AR=llvm-ar RANLIB=llvm-ranlib STRIP=llvm-strip
export CFLAGS='-O2 -fPIE' CXXFLAGS='-O2 -fPIE'
export LDFLAGS='-pie -static-libstdc++ -Wl,-z,max-page-size=16384'
# Never pick host pkg-config libraries during cross-compilation.
export PKG_CONFIG_LIBDIR="$WORK/openssl-install/lib/pkgconfig"
export PKG_CONFIG_PATH=''

curl --fail --location --retry 3 --max-time 600 -o "$WORK/nmap.tar.bz2" "https://nmap.org/dist/nmap-$NMAP_VERSION.tar.bz2"
echo "$NMAP_SHA256  $WORK/nmap.tar.bz2" | sha256sum --check
curl --fail --location --retry 3 --max-time 600 -o "$WORK/openssl.tar.gz" \
  "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
echo "$OPENSSL_SHA256  $WORK/openssl.tar.gz" | sha256sum --check
tar -xjf "$WORK/nmap.tar.bz2" -C "$WORK" --no-same-owner
tar -xzf "$WORK/openssl.tar.gz" -C "$WORK" --no-same-owner

(
  cd "$WORK/openssl-$OPENSSL_VERSION"
  # Static OpenSSL and C++ runtime; system Android libc/libm/libdl/libz remain dynamic.
  perl Configure android-arm64 -D__ANDROID_API__=26 no-shared no-tests no-module \
    --prefix="$WORK/openssl-install" --libdir=lib
  make -j"$JOBS"
  make install_sw
)
(
  cd "$WORK/nmap-$NMAP_VERSION"
  python3 "$ROOT/native-tools/patch-nmap-android.py" "$PWD"
  export CPPFLAGS="-I$WORK/openssl-install/include"
  export LDFLAGS="$LDFLAGS -L$WORK/openssl-install/lib"
  ./configure --build="$(./config.guess)" --host=aarch64-linux-android \
    --prefix=/data/local/tmp/droidmap-nmap \
    --with-openssl="$WORK/openssl-install" --with-libssl-prefix="$WORK/openssl-install" \
    --with-libpcap=included --with-libpcre=included --with-liblua=included \
    --with-libssh2=included --with-libdnet=included \
    --without-ncat --without-nping --without-ndiff --without-nmap-update \
    --without-libnl --disable-shared
  for feature in HAVE_OPENSSL HAVE_LIBSSH2 LUA_INCLUDED PCRE_INCLUDED; do
    grep -q "^#define $feature 1" nmap_config.h || { echo "Required Nmap feature missing: $feature" >&2; exit 1; }
  done
  # Lua's supplied makefile overrides environment AR/RANLIB; use NDK tools explicitly.
  sed -i "s|^AR= .*|AR= $NDK_BIN/llvm-ar rcu|; s|^RANLIB= .*|RANLIB= $NDK_BIN/llvm-ranlib|" liblua/Makefile
  make -j"$JOBS"
  "$NDK_BIN/llvm-strip" nmap
  cp nmap "$OUTPUT/libnmap.so"
  STAGE="$WORK/runtime"
  mkdir -p "$STAGE/nmap-data" "$STAGE/licenses"
  cp nmap "$STAGE/libnmap.so"
  for name in nse_main.lua nmap-service-probes nmap-services nmap-protocols nmap-rpc nmap-mac-prefixes nmap-os-db; do
    test -s "$name"
    cp "$name" "$STAGE/nmap-data/$name"
  done
  cp -R scripts nselib "$STAGE/nmap-data/"
  (cd "$STAGE/nmap-data" && find . -type f -printf '%P\n' | LC_ALL=C sort > "$WORK/nse-files.txt")
  cp "$WORK/nse-files.txt" "$STAGE/nmap-data/nse-files.txt"
  cp LICENSE "$STAGE/licenses/Nmap-LICENSE"
  cp "$WORK/openssl-$OPENSSL_VERSION/LICENSE.txt" "$STAGE/licenses/OpenSSL-LICENSE"
  cat > "$STAGE/build-info.txt" <<INFO
Nmap $NMAP_VERSION
Nmap source SHA-256: $NMAP_SHA256
OpenSSL $OPENSSL_VERSION (static)
OpenSSL source SHA-256: $OPENSSL_SHA256
Local patch: libdnet IPv6 gateway copied into struct in6_addr for Android IN6_* compatibility.
Upstream patch: 29cb897062d0b803e5d00fb6419b131c6fad3123 (NSE version_intensity registry, GH#3557).
Android NDK 27.2.12479018; API 26; ARM64; PIE; 16 KiB maximum page alignment
NSE/Lua, PCRE2, libpcap, libdnet and libssh2 enabled; Ncat/Nping/Ndiff excluded.
Host ELF/data verification does not establish runtime compatibility on a physical device.
INFO
  python3 "$ROOT/tests/verify-nmap-data.py" --assets "$STAGE/nmap-data" --nmap-version "$NMAP_VERSION"
  python3 "$ROOT/tests/verify-nmap-elf.py" "$STAGE/libnmap.so"
  cp "$STAGE/build-info.txt" "$OUTPUT/build-info.txt"
  tar -czf "$OUTPUT/nmap-arm64.tar.gz" -C "$STAGE" libnmap.so nmap-data licenses build-info.txt
)
(cd "$OUTPUT" && sha256sum libnmap.so > libnmap.so.sha256 && sha256sum nmap-arm64.tar.gz > nmap-arm64.tar.gz.sha256)
echo "Nmap Android ARM64 runtime: $OUTPUT/nmap-arm64.tar.gz"
