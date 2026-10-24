# Droidmap

Droidmap is a standalone Android app for discovering devices on a local Wi-Fi network and nearby Bluetooth devices. It combines TCP connect scanning, protocol evidence, optional ARM64 Nmap/Nuclei analysis and ProjectDiscovery HTTPX web metadata collection.

The app uses native Android UI and Java 17, requires Android 8.0+ (API 26), and does not require root. The current app version is **0.17.3**. The home screen has two areas: **Wi-Fi** and **Bluetooth**.

## Contents

- [Wi-Fi workflow](#wi-fi-workflow)
- [Scan settings and limits](#scan-settings-and-limits)
- [Nmap, Nuclei and web analysis](#nmap-nuclei-and-web-analysis)
- [Bluetooth](#bluetooth)
- [Results, sessions and exports](#results-sessions-and-exports)
- [Permissions and platform limitations](#permissions-and-platform-limitations)
- [Build and install](#build-and-install)
- [Tests and validation](#tests-and-validation)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)

## Wi-Fi workflow

1. Connect the phone to the network you want to inspect and open **Wi-Fi**.
2. Enter a private IPv4 address, a bounded CIDR such as `192.168.0.0/24`, or a local IPv6 literal. **Options → Wi-Fi** also offers **Use Wi-Fi network** and **Scan all Wi-Fi IPs**.
3. In **Options → Wi-Fi**, choose a scan type and save the settings. Run **Discover devices**.
4. Discovery performs a best-effort host reachability check, scans the selected TCP ports, and gathers identification evidence. Its compact inventory shows IPs and confirmed-open TCP ports while results arrive.
5. After TCP Discovery completes, expand an IP and select **Nmap**, **Nuclei** or **Analyze Web** beside an eligible port. Nuclei and Analyze Web require HTTP/HTTPS evidence on that same endpoint; Nmap can establish it.
6. Use **Results** for **Full report**, **Export JSON**, **Discover one device** or **History**. **New scan** starts Discovery with the current target and saved settings.

Analysis actions use the completed Discovery baseline for one selected IP/port on the same Wi-Fi network. They do not repeat the network-wide TCP sweep. Nmap performs its own TCP/service checks on that selected port. There are no global Nmap, Nuclei or HTTPX run buttons.

When an observed IP has no open TCP ports, **Search all TCP ports** starts a new Discovery of ports 1–65535 on that IP using the saved timeout and scan mode. It replaces the current Discovery session without changing saved scan settings. No service analysis starts until an open port is verified.

The active action becomes **Stop**. After completion, +/- controls expand or collapse results. **Back to home** and Android Back return to the two home choices without stopping an active scan. **Options** and **Clear All** remain in the header; settings cannot change during a running operation. The UI permits one network or Bluetooth operation at a time.

## Scan settings and limits

### Profiles

| Profile | Selected TCP ports | Behavior |
| --- | --- | --- |
| Quick | 19 common ports | Fast mode; shorter discovery and identification; no TCP timeout retry |
| Detailed | 39 ports | Complete mode; longer discovery and identification; one retry for TCP timeouts |
| All ports | 1–65535 | Complete mode; can take hours across a network |
| Custom | Comma-separated ports/ranges | Explicit ports and optional extra discovery/retries |

The connection timeout defaults to **200 ms** and accepts **100–3000 ms**. Advanced settings expose automatic speed adjustment. Saved custom choices are preserved; mixed configurations appear as Custom. **Save** applies edits; Cancel, Back or dismissing the dialog discards draft settings.

Fast mode on multiple IPs tests up to three selected TCP ports per host before scanning the rest. Explicit TCP refusal, a successful connection or prior discovery evidence can establish a responder. Remaining ports on silent IPs are marked **SKIPPED**. A single-IP Fast scan checks all selected ports. Complete mode checks every selected host/port unless cancelled; failed reachability checks do not exclude silent hosts.

Only `NO_RESPONSE` checks receive the Complete-mode retry, with twice the timeout capped at 3000 ms. Progress counts unique host/port checks rather than attempts. Adaptive scanning adjusts concurrency and may increase subsequent timeouts based on observations; it does not shorten the configured timeout. Quick mode's silent-host skipping still applies when adaptive scanning is enabled.

### Targets and bounds

| Item | Bound or rule |
| --- | --- |
| IPv4 targets | RFC 1918 literals; /24–/32; at most 256 addresses |
| Network/broadcast addresses | Excluded for /24–/30; all addresses retained for /31 and /32 |
| Scan all Wi-Fi IPs | Uses the actual /24–/32 subnet; rejects larger networks |
| Use Wi-Fi network | Bounded shortcut; larger subnets use the local /24 |
| IPv6 | Individual local Wi-Fi unicast addresses and observed neighbors; no subnet enumeration |
| Additional discovered IPv6 addresses | At most 256 |
| Selected TCP ports | Up to 65535 per IP |
| Concurrent TCP checks | At most 32 |
| Advertised endpoints | At most 16 per device, separately TCP-verified |
| Analysis session | At most 128 distinct tool/IP/port entries |

IPv6 admission checks the connected Wi-Fi link and prefix; link-local addresses require interface scope. IPv6 /64 sweeps and public IPv4 targets are not supported.

### Identification evidence

Discovery can collect mDNS/NSD names and TXT metadata, SSDP/UPnP names/manufacturer/model, Wi-Fi-scoped reverse DNS, HTTP titles/server headers, TLS metadata, SMB, RTSP, IPP, NetBIOS and passive service banners. Advertised endpoints outside the selected port list are verified before being added as open TCP ports.

Evidence retains its source. Reported identity, inferred device type and corroboration are distinct; matching metadata is not authenticated identity. DNS names and port numbers alone do not establish a hardware vendor. Unknown devices remain unknown.

MAC observations may come from NetBIOS, IPv4/IPv6 neighbors or Nmap. The bundled offline vendor catalog labels eligible address prefixes. Locally administered/random addresses are marked accordingly and do not establish factory identity; Android may prevent MAC collection.

## Nmap, Nuclei and web analysis

Native tool runtimes are packaged for **Android ARM64 (`arm64-v8a`)**. A missing runtime or unsupported ABI is reported as unavailable. A normal Gradle build does not download these runtimes automatically.

### Nmap

Nmap runs two profiles on the selected endpoint:

1. Service/version detection with TCP connect scanning and the packaged default/safe NSE selection.
2. Vulnerability detection, only if the preceding Nmap scan still confirms an open port. NSE chooses applicable scripts using port and detected-service rules.

The packaged script expressions are:

```text
Services:
(default or safe) and not broadcast and not external and not targets-*

Vulnerabilities:
(vuln and safe) and not brute and not dos and not intrusive and not exploit and not broadcast and not external and not targets-*
```

**Options → Nmap** exposes service/version intensity **0–9** (default **2**, Light) and additional Nmap arguments. Arguments are split into argv and passed directly to `ProcessBuilder`; no shell is invoked. Additional arguments are not validated against an option allowlist and can change Nmap behavior, so the packaged defaults describe runs without such overrides.

The runtime configuration is [nmap-command-templates.json](app/src/main/assets/nmap-command-templates.json), parsed by `NmapCommandsJson` and executed by `NmapRunner`. Editing it requires rebuilding the APK; there is no runtime file-import editor. Descriptive fields such as `requires` and `skipWhen` document behavior enforced in Java.

Both packaged profiles have **no app-imposed process deadline** (`processTimeoutSeconds: 0`). Nmap uses its own timing; the native TCP scanner's 200 ms timeout is not a Nmap execution limit. Stop terminates the active process. Templates also support optional 1–300 second process deadlines, bounded output capture and bounded output-reader waits.

The technical log records the profile, exit code, duration, readable output, separate errors/warnings and exact arguments. XML is written to a separate temporary file for parsing, then removed. A successful process exit does not prove successful XML parsing, successful execution of every NSE script or absence of vulnerabilities.

The source-built Nmap runtime pins Nmap **7.992**, OpenSSL **3.5.9** and NDK **27.2.12479018**. It includes an Android libdnet compatibility patch and the upstream version-intensity registry fix. **Rebuild/publish the native runtime before rebuilding the app** to deliver native fixes; replacing NSE files alone cannot fix the executable. See [Nmap runtime build instructions](native-tools/NMAP.md).

### Nuclei

**Options → Nuclei** selects offline HTTP coverage groups. All three are enabled by default; each group contains seven bundled templates. Saved group selections keep their existing meaning and include the additional checks in those groups:

| Group | Checks |
| --- | --- |
| File exposures | Git HEAD/configuration, environment configuration, Subversion entries, Mercurial configuration, npm credentials, WordPress configuration backup |
| HTTP configuration | Missing security headers, directory listing, Apache status counters, credentialed CORS trusting the probe origin, Docker container listing, Kubernetes namespaces, CouchDB database names |
| Diagnostic interfaces | OpenAPI, Spring Actuator discovery/environment, Prometheus metrics, PHP information, Nginx counters, Jolokia version |

The explicit allowlist uses only the selected template files. Bundled templates send GET requests to fixed paths on the selected endpoint and do not follow redirects. The CORS check sends a synthetic Origin header; it does not contact that origin. This is a bounded set of 21 templates, not the complete upstream template collection or a complete CVE assessment. API listings are checked without supplied credentials; they do not establish write access. Empty listings or nonstandard endpoint paths can remain undetected.

OpenAPI, Actuator discovery, Prometheus/Nginx counters, Jolokia version and missing headers are informational. PHP configuration, Actuator environment metadata and credential/configuration exposures are review findings with descriptions explaining their limits and suggested remediation. Sanitized Actuator values are not assumed to contain secrets, and CORS headers alone do not establish data theft. No secret values are extracted into findings. New checks require HTTP 200 plus endpoint-specific response signatures; generic login pages, protected responses and redirects are not positive matches. Each result still requires review in its deployment context.

Exports record selected groups, template filenames and configured counts. `successfulTemplateCount` is unavailable (`null`); configured coverage and process completion are not counts of successful checks. Nuclei has no app-wide execution deadline; use Stop to cancel.

See [Nuclei packaging notes](native-tools/NUCLEI.md) and the current [Android workflow](.github/workflows/android.yml) for runtime acquisition.

### Analyze Web (ProjectDiscovery HTTPX)

Analyze Web collects HTTP status (including 401/403), title, server, content type, response timing, estimated technologies, redirect Location and available TLS metadata from the selected confirmed HTTP/HTTPS endpoint.

It uses the confirmed scheme and literal IP/port, preserves IPv6 interface zones, and displays redirects without following them. Protocol fallback, CDN lookup, updates and cloud upload are disabled. Technology fingerprints are estimates.

The patched runtime enables TLS trust and name validation. Self-signed/untrusted certificates or certificates that do not match the IP can prevent HTTPS metadata collection; those outcomes are failed/incomplete. Android certificate-store behavior still needs physical-device validation.

Reads are limited to **256 KiB**, process output to **512 KiB**, each request to **10 seconds** with no retries, and the process to **45 seconds**. Stop forcibly terminates the process. Reports retain bounded metadata rather than raw response bodies.

### Progress and diagnostics

Discovery displays stages and TCP progress. Tool execution provides current-phase information and recent timestamped diagnostics, with updates throttled to avoid excessive UI work. Nmap emits verbose stages and statistics every five seconds. Full captured Nmap text remains available from its result details.

Elapsed time is not an estimate of remaining time. A progress bar is indeterminate when a reliable total is unavailable. Cancellation retains partial results.

## Bluetooth

Open **Bluetooth → Scan Bluetooth**. The default mode is **Both (BLE + Classic)**. In **Options → Bluetooth**, choose BLE, Classic or Both and configure the following independently:

| Setting | Default | Choices |
| --- | --- | --- |
| Discovery duration | 30 seconds | No limit, 5, 10, 15, 30, 60, 120 or 300 seconds |
| SDP response timeout | 30 seconds | Same choices |
| GATT inspection per attempt | 30 seconds | Same choices |
| Characteristic read timeout | 30 seconds | Same choices |

Saved choices, including No limit, are retained. No limit waits for Stop or an Android outcome; Android's own Bluetooth limits still apply. The GATT budget includes connection, service discovery and reads for that attempt.

Discovery merges observations by address and labels paired-but-unobserved devices as cached. Both mode keeps BLE registered while repeating Classic inquiry rounds. The panel distinguishes scan registration from actual reception and shows device counts, duration and the nearest active countdown. **Reception and timing details** expands observation counts, reception timestamps and phase timers; stopped timers stay frozen.

Collected information includes:

- BLE legacy/extended advertisements, supported PHY metadata, names, RSSI/min/max, timestamps, observation counts, connectability, flags, TX power, SID and data completeness.
- Advertised/solicited UUIDs, service/manufacturer data, raw AD structures and up to eight distinct raw advertisement samples per device.
- iBeacon and Eddystone fields plus bounded vendor payload interpretation, including Microsoft and Samsung formats where recognized.
- Classic discoverable devices, class, pairing state and cached service UUIDs.

Company IDs identify advertisement owners; decoded fields and rotating addresses do not establish a physical device, user account or stable identity. Discovery cannot find every silent, hidden or out-of-range device.

After discovery, **Inspect services (GATT / SDP)** is an explicit per-device operation. It queries Classic SDP UUIDs where applicable, discovers connectable BLE services/characteristics/descriptors and reads supported standard Device Name, Battery Level and Device Information values. It does not automatically read custom values, write characteristics, subscribe, initiate pairing or authenticate. Protected values may be unavailable.

Inspection is bounded to 128 services, 512 characteristics, 64 descriptors per characteristic and 32 standard reads. Eligible connection-establishment failures can receive one controlled retry after two seconds; failures after a successful connection do not trigger that retry. A read timeout ends that device's inspection while retaining partial services. Stop cancels deadlines, queued work and retries, and closes the active GATT connection.

Runs hold at most **512 unique addresses**; omitted observations are counted. **Export JSON** saves Bluetooth results separately from network results, including raw observations, effective settings, timing and partial inspection outcomes.

## Results, sessions and exports

### Reading results

| State | Meaning |
| --- | --- |
| OPEN | A TCP connection succeeded |
| CLOSED | An explicit connection refusal was received |
| NO_RESPONSE | The TCP connection timed out; the device may still exist |
| ERROR | Another connection failure, such as a route or permission problem |
| SKIPPED | A selected check was omitted by Fast-mode silent-host filtering |

An open port is not a vulnerability. No response is not proof that a device is offline. A completed command, missing NSE findings or zero Nuclei matches do not establish that an endpoint is secure.

Discovery is the complete inventory for the current scan. Nmap, Nuclei and Web analysis panels contain only their analyzed endpoints, with expandable findings, coverage and diagnostics. Full report and JSON combine source evidence and the latest analyses.

### Session lifetime

Latest attempts accumulate by **tool/IP/port**. Rerunning replaces that entry and its stale findings while preserving other analyses. At 128 entries, new combinations are rejected; existing entries can still be rerun. Export and start Discovery again to reset the session. Tool cancellation/failure belongs to that endpoint and does not cancel the completed Discovery baseline.

Starting a new Discovery clears the analysis session. **Clear All** removes results, scan history and retained Nmap output while keeping settings. A fresh app screen clears completed scan files, history and completed Bluetooth observations; **export before reopening the app** if you need to retain them. Activity recreation restores the current session, and an active foreground operation is preserved.

Network snapshots use private files and atomic persistence for completed/normal-cancellation results; an interrupted marker is not a completed scan and does not silently restart work. Bluetooth observations remain in memory while the process lives and are not a durable history.

History compares only compatible completed scans with matching target, ports, mode, timeout, adaptive settings and Wi-Fi session scope. Partial/cancelled scans do not become complete baselines. Missing entries mean **not observed**, not definitively offline. History is subject to the fresh-screen clearing behavior above.

### Export format

Network exports include initial checks, separately verified `advertisedEndpointChecks`, sourced `devices` evidence, notices, completion metadata, history comparison and `analysisRuns`.

Small scans use **schema 5** with full `checks`. Large scans use **schema 7** with lossless `packedChecks`, including Fast-mode skipped checks; the summary `checks` array retains open checks and representative closed checks. Older schema 6 reports remain supported. Consumers should inspect `schemaVersion` and the declared packed encoding instead of assuming that `checks.length` equals the completed-check count.

Nmap text logs use a separate bounded cache (64 MiB, eight executions) and can expire before report evidence. Export does not make referenced private log files portable.

JSON export uses Android's document picker and requires no broad storage permission.

## Permissions and platform limitations

- Network scans use Internet/network-state access and a `connectedDevice` foreground service started from the visible app.
- Android 13+ requests notification permission. Denial hides notification-drawer progress/cancellation; in-app Stop remains available.
- Bluetooth requires Bluetooth enabled, Nearby Devices on Android 12+, precise location permission and location services. The manifest omits `neverForLocation` so Android does not filter some beacon formats. No location coordinates are collected.
- Bluetooth hardware is optional. Android/controller limitations, background throttling and screen-off behavior can reduce discovery; keep the screen on for the broadest BLE collection.
- Wi-Fi client isolation, VPN routes, firewalls, multicast filtering and Android neighbor-table restrictions affect results. The app does not guarantee MAC visibility or complete device enumeration.
- Rotation, backgrounding and returning home do not themselves cancel foreground scans. Process termination, force-stop and platform restrictions can still interrupt work.

Only inspect networks and devices you are authorized to assess. Protocol identification probes are bounded and read-only; Nmap's selected NSE categories are not a guarantee of zero impact.

## Build and install

### Requirements

| Component | Repository configuration |
| --- | --- |
| Java | JDK 17 |
| Android SDK | Platform 35, build tools 35.0.0 |
| Gradle wrapper | 9.7.1 |
| Android Gradle Plugin | 8.9.2 |
| Minimum / target Android API | 26 / 35 |
| HTTPX cross-build | Go 1.26.x, NDK 27.2.12479018, Linux x86-64 host |
| Supporting tools | Python 3, Git, GitHub CLI; native compiler tools for source cross-builds |

Set `ANDROID_HOME` or an untracked `local.properties` with `sdk.dir=...`. Open the repository root in Android Studio, or use the commands below from that root.

### Development checks

```bash
bash tests/run.sh
bash gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug --no-daemon
```

On Windows, use `gradlew.bat` for Gradle tasks. Without an explicitly configured keystore, a normal debug build can use a different signing identity and cannot replace the installed update APK. Native tools are unavailable unless their matching Android runtimes/data have been integrated.

### Complete ARM64 runtime preparation

The [Droidmap Android workflow](.github/workflows/android.yml) is the reference for the complete APK build. For a local Linux environment with the required tools:

1. Integrate the published Nmap runtime:
   `bash native-tools/build-nmap-android.sh`. This uses GitHub CLI to obtain the `nmap-android-arm64` release and verifies the archive, executable and matching NSE data.
2. Install the genuine Android Nuclei executable:
   `bash native-tools/install-nuclei-android.sh /path/to/nuclei-arm64`.
   CI obtains it from the pinned repository archive when present, or from the `nuclei-android-arm64` release.
3. Compile/test the pinned patched HTTPX source:
   `bash native-tools/build-httpx-android.sh`.
4. Build with the existing update signing key as shown below.

The Nmap source build is a separate manual **Build Nmap for Android ARM64** workflow. Publish a new runtime first, then run **Droidmap Android**. Native executable names such as `libnmap.so` are used for APK extraction; these tools run as processes rather than JNI libraries.

CI runs on pushes to `main` and via `workflow_dispatch`; pull requests do not automatically trigger this workflow. It integrates all three runtimes, checks the fixed signing identity, runs scanner checks and Gradle tests/build/lint, validates packaging, and uploads **Droidmap-update-APK** containing **Droidmap-update.apk**. Missing runtime releases or the original signing key fail the build.

### Preserve installed-app updates

The current update identity is **`com.netmap.android`**. Restore the original keystore and use:

```bash
NETMAP_DEBUG_KEYSTORE=/absolute/path/to/netmap-debug.keystore \
  bash build-apk.sh --no-daemon
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The default key path is `.signing/netmap-debug.keystore`. The script verifies the pinned certificate before building, then checks the final APK through [verify-update-apk.sh](tools/verify-update-apk.sh). Never generate a replacement key for routine updates or commit signing keys.

The older **`com.netmap.android.dns`** installation is a separate identity and requires its original key:

```bash
NETMAP_APK_PROFILE=legacy-dns \
NETMAP_DEBUG_KEYSTORE=/absolute/path/to/original-dns.keystore \
  bash build-apk.sh --no-daemon
```

`-PsideBySideInstall=true` adds the `.dns` suffix; it is not interchangeable with the current package. Both public certificate pins are in [apk-identity.sh](tools/apk-identity.sh). A documentation-only update does not change package IDs, signing configuration or version numbers.

For an emulator setup, see [Android emulator instructions](docs/android-emulator.md). Emulator checks cannot replace real Wi-Fi/Bluetooth and native ARM64 device validation.

## Tests and validation

| Check | Purpose |
| --- | --- |
| `bash tests/run.sh` | Plain Java scanner, bounds, packed results, identification, Nmap, Bluetooth and MAC checks; requires JDK and Python 3, no Android SDK |
| `bash gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug --no-daemon` | Unit tests, APK compilation and Android lint |
| `python3 tests/test-apk-identity.py` | Signing/package guard checks |
| `python3 tests/test-nmap-data.py` | Nmap data and archive validation checks |
| `python3 tests/test-install-nmap-runtime.py` | Nmap runtime installer checks |
| `python3 tests/test-nuclei-templates.py /path/to/host/nuclei` | Bundled templates against local HTTP fixtures; requires a host-native Nuclei executable |
| `python3 tests/verify-nmap-data.py --apk app/build/outputs/apk/debug/app-debug.apk --nmap-version 7.992` | Packaged Nmap data/runtime consistency |

For a host-native Nmap built from the patched source, the NSE regression check is:

```bash
python3 tests/test-nmap-nse.py --binary /path/to/host/nmap --data-dir /path/to/nmap-7.992
```

It exercises category-based selection and version-intensity registry behavior. HTTPX's build script also runs a host smoke test before Android cross-compilation.

Builds and host tests do not establish on-device native compatibility, certificate-store behavior, real multicast reception or Bluetooth stack behavior. Validate those on physical devices and report which checks actually ran. For documentation-only changes, verify commands, paths and descriptions against the source; generating an APK is unnecessary.

## Architecture

The Android project lives at the repository root; it is independent of any .NET backend. Production UI uses Android framework components, with dnsjava for scoped PTR resolution.

Java filenames below are relative to [app/src/main/java/com/netmap/android](app/src/main/java/com/netmap/android).

| Area | Main components |
| --- | --- |
| Activity and UI | `MainActivity`, `OptionsPage`, `DeviceResultsRenderer`, `BluetoothPanel`, `ReportPresentation` |
| Network lifecycle | `ScanService`, `ScanSnapshot`, `LatestScanStore` |
| Scan planning/settings | `ScanPlan`, `ScanSettings`, `ScanSettingsStore`, `ScanOptionsEditor` |
| TCP work and scheduling | `HostDiscovery`, `TcpScanner`, `AdaptivePolicy`, `PackedScanResults` |
| Identification/protocols | `DeviceIdentifier`, `DeviceEvidence`, `DeviceProfile`, `DeviceConfidence`, `IdentificationStatus`, `ProbeContext`, protocol probes |
| Local discovery and names | `NsdDiscovery`, `SsdpDiscovery`, `WifiIpv6Scope`, `Ipv6NeighborDiscovery`, `WifiReverseDns` |
| MAC metadata | `MacAddresses`, `Ipv4MacDiscovery`, `MacVendorCatalog` |
| Nmap | `NmapEnricher`, `NmapCommandsJson`, `NmapCommands`, `NmapRunner`, `NmapDataFiles`, `NmapXmlParser`, `NmapOutputStore` |
| Nuclei and HTTPX | `NucleiEnricher`, `NucleiTemplates`, `HttpxEnricher`, `HttpxResult`, `WebEndpoints` |
| Session/report/export | `SessionAnalyses`, `ScanReport`, `ScanHistory`, `ScanHistoryDialog`, `ReportExporter`, `ExportRequest` |
| Bluetooth lifecycle/evidence | `BluetoothScanService`, `BluetoothSettings`, `BluetoothAdvertisement`, `BluetoothVendorDecoder`, timing and inspection helpers |
| Native builds and identity | [native-tools](native-tools), [tools](tools), [Android CI](.github/workflows/android.yml) |
| Tests | [Plain Java/Python checks](tests), [Gradle unit tests](app/src/test/java/com/netmap/android) |

Services own execution and cancellation across Activity recreation. Immutable snapshots and report helpers keep scan state separate from rendering. Protocol probes share bounded deadlines/read limits and active socket ownership. Session analyses aggregate evidence without granting authorization beyond the completed Discovery baseline.

The activity and foreground services still coordinate substantial behavior; changes to settings, lifecycle, report format or tool authorization need checks across those boundaries. Contributor invariants and signing rules are documented in [AGENTS.md](AGENTS.md).

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| No devices or ports found | Wi-Fi/subnet, client isolation, VPN/firewall, timeout and Quick-mode skips; try Detailed or a single-IP All ports scan |
| Analysis buttons unavailable | Complete Discovery on the current target/network; select a verified-open port; Nuclei/HTTPX also need web evidence |
| Nmap exits 0 but scripts fail | Inspect script output, warnings and XML status; verify the patched native runtime was rebuilt and integrated |
| Nmap seems to run indefinitely | Packaged profiles have no process deadline; use Stop and inspect the technical log |
| HTTPS web analysis fails | Verify trust chain and certificate/IP name match; rejection is not a successful security assessment |
| Bluetooth has no advertisements | Check permissions, location services, transport mode, radio support and screen/background restrictions; cached paired devices are not reception evidence |
| GATT error 133 | Android reports a generic stack error; inspect per-stage/attempt evidence rather than assuming a specific cause |
| Results disappeared after reopening | Fresh screens clear completed sessions/history; export JSON before reopening |
| APK will not update the installed app | Match both package ID and original certificate; restore the proper key/profile and use `build-apk.sh` |
