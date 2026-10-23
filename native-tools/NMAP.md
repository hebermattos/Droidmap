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

The patch script also backports upstream commit
[`29cb897062d0b803e5d00fb6419b131c6fad3123`](https://github.com/nmap/nmap/commit/29cb897062d0b803e5d00fb6419b131c6fad3123)
for [Nmap issue #3557](https://github.com/nmap/nmap/issues/3557). Nmap 7.992's
lazy loading removed the global Lua `nmap` table, but `version_intensity()` still
read it. Capturing `nmap.registry` as a closure upvalue restores version-script
rules, including `rpcinfo`, `rpc-grind`, `skypev2-version` and `vmware-version`.
The patch fails on unexpected source contents instead of silently skipping a fix.
Both patches are recorded in the runtime's `build-info.txt`.

**After this source patch, rebuild and publish the Nmap runtime first, then run
Droidmap Android again.** A push to main alone still downloads the previously
published runtime. Replacing NSE data without rebuilding the native executable
does not fix this regression.

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

Always keep the binary and data from the same archive together. **Droidmap Android**
downloads `nmap-arm64.tar.gz` and its checksum from the published release, checks
archive integrity, Android ELF compatibility, version and data manifest, then
packages the binary and matching files into the APK. Missing releases, mismatched
checksums and invalid bundles fail the build; no older Nmap fallback is used.
The final APK check verifies that the packaged binary hash matches its runtime
metadata, alongside the existing package/signing identity checks.

After publishing a new Nmap runtime, run **Droidmap Android** (or push the app
changes to main) to produce the updated APK. Source compilation and APK packaging
remain separate actions. The app's private NSE cache is identified by the runtime
archive hash: a new runtime stages a complete new directory, activates it only
after copying all files, then removes legacy/previous caches. A failed copy keeps
the previous cache and reports the failure. No manual app-data clearing is needed.
Package IDs and signing keys are preserved. Physical-device validation of NSE
behavior is still required.

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

For a host-native Nmap 7.992 build made from the same patched source, the NSE
regression check runs a synthetic pre-scan script on loopback with discovery
and port scanning disabled, then validates both packaged selection expressions:

```bash
python3 tests/test-nmap-nse.py --binary /path/to/host/nmap --data-dir /path/to/nmap-7.992
```

The test selects the synthetic script by category: selecting it by explicit name
would bypass the affected registry lookup and hide the regression. It checks both
`--version-intensity` and the `script-intensity` override. This host check cannot
execute the Android ARM64 binary or replace physical-device validation.
