# Run Droidmap in the Android Emulator

## Android Studio

1. Open the repository root in Android Studio.
2. In SDK Manager, install Android SDK Platform 35, Build-Tools 35.0.0, Android SDK Platform-Tools and Android Emulator.
3. Select JDK 17 as the Gradle JDK and allow Gradle sync.
4. In Device Manager, create a phone AVD using an API 35 system image matching your computer architecture (x86_64 for Intel/AMD, arm64-v8a for Apple Silicon).
5. Start the AVD, select the app run configuration and click Run.

For an update-compatible build, restore the original key to `.signing/netmap-debug.keystore`, set `NETMAP_DEBUG_KEYSTORE` to its absolute path **before starting Android Studio**, and add `sideBySideInstall=true` to your local user Gradle properties (`~/.gradle/gradle.properties`). Never commit keys or machine-specific paths. Without these settings, Android Studio uses its local debug key and the base package ID; that build cannot update the installed DNS package.

## One-command launch (Linux/macOS or WSL with a Linux SDK)

Set `ANDROID_HOME` to the SDK directory displayed in Android Studio. Restore the original signing key before running:

```bash
bash run-emulator.sh --list
bash run-emulator.sh YOUR_AVD_NAME
```

An optional second argument selects an even emulator port, for example `5556`. The script runs the existing certificate-checked build, unit tests and lint, starts or reuses the named AVD, waits up to four minutes for boot, installs using `adb install -r` and opens the launcher activity. It addresses only that emulator and never uninstalls the app or replaces its signing key.

On Windows, use Android Studio and its Windows SDK directly.

## Network and native tools

The emulator has a virtual network; it does not reproduce the phone's physical Wi-Fi link. Droidmap binds discovery to its observed Wi-Fi network, so automatic subnet selection, multicast/mDNS, IPv6 neighbors and MAC discovery can differ or be unavailable. A private LAN IP may be reachable through the host, but this does not establish equivalent discovery coverage. Use a physical Android device on your Wi-Fi to validate real LAN discovery.

The packaged Nmap binary is ARM64. An x86_64 emulator can exercise the UI and Java code, but Nmap requires a compatible ARM64 runtime; do not assume native translation is available. Nuclei similarly requires a packaged binary compatible with the AVD ABI. Missing native binaries produce tool notices. Local builds do not automatically download CI-packaged native assets.
