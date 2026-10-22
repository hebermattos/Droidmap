# Building Nmap for Android ARM64

Run **Actions → Build Nmap for Android ARM64 → Run workflow** after the workflow
has been merged into the default branch. This manual workflow follows the Nuclei
build/publish pattern; it does not require custom secrets beyond GitHub's token.

The build pins Nmap **7.992**, OpenSSL **3.5.9** and Android NDK **27.2.12479018**.
Both source archives are verified against SHA-256 values stored in the build
script. The result targets Android API 26 and ARM64, matching the app's minimum
Android version. OpenSSL and the C++ runtime are linked statically. NSE/Lua,
PCRE2, libpcap, libdnet and libssh2 are included. Ncat, Nping and Ndiff are not built.

A small checked source patch converts libdnet's IPv6 gateway to the correct
`struct in6_addr` type before using Android's `IN6_*` macros. It does not change
the gateway address or route semantics.

The workflow checks the ELF architecture, Android linker, PIE format, 16 KiB
segment alignment and shared-library dependencies. It also verifies the complete
NSE data manifest before packaging and again after extracting the archive.
Compilation and these checks do not establish on-device runtime compatibility.

The `nmap-android-arm64` artifact and the GitHub release with the same tag contain:

- `libnmap.so`: the Android executable, named for APK native-library extraction.
- `libnmap.so.sha256`: binary checksum.
- `nmap-arm64.tar.gz`: the executable, matching `nmap-data/` scripts/libraries,
  upstream license notices and source/toolchain information.
- `nmap-arm64.tar.gz.sha256`: complete runtime archive checksum.
- `build-info.txt`: pinned versions and source hashes.

Always keep the binary and data from the same archive together. The action
publishes an independent runtime; the APK workflow's existing pinned Nmap 7.31
packaging remains unchanged. Switching the APK to a new release is a separate
integration step, including refreshing any previously installed private Nmap
script cache and testing NSE behavior on a physical Android device. This action
does not build an APK or change package IDs, app versions or signing keys.

For a local Linux x86-64 cross-build, install `build-essential`, `perl`,
`pkg-config`, `flex`, `bison` and the pinned NDK, then run:

```bash
ANDROID_NDK_HOME=/absolute/path/to/android-ndk-r27c \
  bash native-tools/compile-nmap-android.sh
```

Output defaults to `dist/nmap-android-arm64`. `NMAP_OUTPUT_DIR` can override it;
`NMAP_BUILD_JOBS` controls build parallelism. Temporary sources are isolated in a
unique directory and removed when the script exits. Do not commit generated
binaries or archives.
