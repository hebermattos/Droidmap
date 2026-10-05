# Droidmap contributor and agent guide

This file applies to the entire repository. Read the current checkout before changing behavior; README descriptions and feature branches can differ. User instructions take precedence over this guide.

## Project scope

- Droidmap is a standalone Android app for private IPv4 discovery, TCP connect scanning and evidence-based device identification.
- The Android project lives at the repository root. It is independent of the Netmap .NET pipeline; do not recreate an `android/` subproject or copy backend dependencies into it.
- Keep code, UI text, documentation and GitHub descriptions in English. Communicate with the user in their requested language.
- Prefer focused Java/native Android changes and the existing Gradle wrapper. Do not add frameworks or dependencies without a concrete need.

## Code map

| Location | Responsibility |
| --- | --- |
| `app/src/main/java/com/netmap/android/MainActivity.java` | Activity lifecycle, user actions and service snapshots |
| `ScanSettings.java`, `ScanSettingsStore.java`, `ScanSettingsDialog.java` | Immutable validated settings, preferences/migration and settings editor |
| `DeviceResultsRenderer.java`, `ScanHistoryDialog.java`, `ReportExporter.java`, `ExportRequest.java` | Device cards, history presentation and run-scoped export state/I/O |
| `ScanPlan.java` | Target/port validation, scan modes, retries and budgets |
| `TcpScanner.java`, `AdaptivePolicy.java` | Bounded TCP connections, scheduling, progress and cancellation |
| `DeviceIdentifier.java` | Discovery/identification scheduling, protocol routing and advertised endpoint checks |
| `SsdpDiscovery.java`, `*Probe.java`, `ProbeContext.java` | Protocol operations and shared deadlines, read bounds and socket ownership |
| `DeviceEvidence.java`, `DeviceProfile.java`, `DeviceConfidence.java`, `IdentificationStatus.java` | Bounded observations, provenance and typed identity/completion decisions |
| `NsdDiscovery.java` | Android mDNS/NSD discovery and resolution |
| `ReverseDns.java`, `WifiReverseDns.java` | dnsjava PTR resolution, scoped caching and Wi-Fi DNS binding |
| `Ipp.java`, `HttpReply.java`, `NetBios.java` | Protocol encoding and bounded reply parsing |
| `ScanHistory.java` | Local summaries and comparisons between comparable scans |
| `app/src/main/res/`, `app/src/main/AndroidManifest.xml` | Theme, icons, resources, permissions and components |
| `app/src/test/`, `tests/` | Gradle unit tests and plain Java scanner/identification checks |

Java filenames in the table are relative to `app/src/main/java/com/netmap/android/` unless a full repository path is given. On checkouts containing `ScanService`, `ScanSnapshot`, `ScanReport` and `LatestScanStore`, these own background scanning, immutable state, report formatting and durable latest results. Keep that ownership independent of the activity lifecycle.

## Scan and identification invariants

- Retain RFC 1918 literal IPv4 validation and the /24–/32 target limit. Loopback is allowed only inside test harnesses, not through the app target field.
- Preserve configured bounds: at most 256 target addresses, 256 selected ports, 32 concurrent TCP checks and 16 advertised endpoints per device. Keep observation, parser, discovery, DNS and history limits explicit.
- Check every selected host/port unless cancelled. Performance optimizations must not silently omit silent addresses or ports. Keep retry behavior and progress counts consistent with `ScanPlan`.
- Respect the entered timeout and custom port selection. Keep factory defaults and one-time preference migrations consistent with the implemented UI and README; do not reset saved custom values on every launch.
- `OPEN` requires a successful TCP connection. Explicit refusal is `CLOSED`; timeouts and other failures must not establish reachability. Missing observations do not prove a device is offline.
- Use typed confidence/status values for decisions; format their labels only at evidence, UI or report boundaries. Preserve schema 5 labels when refactoring.
- Preserve source evidence and distinguish reported metadata from inferred identity. Port numbers or DNS names alone must not identify hardware or manufacturer. Unknown devices remain unknown.
- Preserve initial TCP checks separately from advertised endpoint checks in JSON. Verify announced TCP endpoints before labeling them open; a UDP announcement is not an open TCP port.
- Keep probes read-only. Do not send print jobs, modify devices, authenticate or exploit vulnerabilities as part of identification.
- Retain same-sender UPnP URL restrictions, parser byte/deadline limits, redirect restrictions and TLS validation. Do not send plaintext probes to advertised HTTPS/IPPS services.
- Keep PTR queries bound to matching Wi-Fi/private DNS servers, with bounded aliases, TCP fallback, TTL and network-scoped caching. Do not introduce public DNS fallback for local device names.
- Cancellation must release active sockets, workers and discovery callbacks promptly. Avoid orphan executors or duplicate discovery jobs.

## Android lifecycle and UI

- Keep the compact black background/white text interface, Options menu and inline expandable device details. Preserve selectable values, readable labels, accessibility and small-screen scrolling.
- Keep network and disk work off the main thread. Bound UI/notification update frequency and avoid repeated full-check traversals inside per-device operations.
- If background scanning is implemented in the checkout, keep one active scan owned by the service. Activity recreation or detachment must not cancel it. Scope notification cancellation to the current run.
- Start foreground work from the implemented user action, with the appropriate manifest service type, permissions and notification. Handle notification permission denial without pretending notifications are visible.
- Persist completed/normal-cancellation results atomically. Restore interrupted running markers as interrupted; do not claim completion or restart scans silently after process termination.
- Keep partial previews distinct from durable final reports and history baselines. Preserve full export data and avoid putting large reports into activity Bundles.
- Compare history only for matching normalized targets and port selections. Cancelled/incomplete scans must not become complete comparison baselines.

## Build and validation

Use JDK 17 and the Android SDK versions configured in Gradle/CI (currently platform 35 and build tools 35.0.0). Set `ANDROID_HOME` or an untracked `local.properties` as needed. Run from the repository root:

```bash
bash tests/run.sh
bash gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug --no-daemon
```

- For scanner, identifier or protocol changes, run both the plain Java checks and Gradle tests/build/lint. Add targeted tests for changed coverage, bounds, cancellation, retries, parsing or persistence behavior.
- For Android UI, manifest or resource changes, build and lint the app. Validate changed interactions on a device/emulator when available; report when that validation was not performed.
- For documentation-only changes, verify commands, filenames and references against the checkout. Do not generate an APK or claim runtime tests for a documentation-only change.
- Do not lower existing test/coverage gates to make a change pass. Do not invent coverage percentages or device-test results.
- Keep benchmarks reproducible and identify workload, timeout, concurrency and measurement method. Separate simulated timings from real Wi-Fi measurements.
- CI currently runs on pushes to `main` and via `workflow_dispatch`; preserve that trigger policy unless the user asks to change it. Check relevant CI results after a requested merge.

## APK compatibility and signing

- Preserve namespace `com.netmap.android`, base application ID `com.netmap.android` and the `sideBySideInstall` suffix `.dns` unless an explicit migration is requested.
- User update APKs use `com.netmap.android.dns`. Build them with the saved signing key and `-PsideBySideInstall=true`.
- Prefer the existing signing-checking script:

```bash
NETMAP_DEBUG_KEYSTORE=/absolute/path/to/netmap-debug.keystore bash build-apk.sh --no-daemon
```

- The script defaults to `.signing/netmap-debug.keystore`. Never generate a replacement key silently. Never commit signing keys, signing backups or generated build output.
- Verify delivered APK package ID, version and signing certificate. CI uses an ephemeral debug key and its artifact is not an update-compatible replacement for the user APK.
- Increase `versionCode` for delivered app changes and set the matching `versionName`; documentation-only changes do not require a version bump.

## Documentation and handoff

- Update README instructions when changing settings, menus, scan behavior, limits, permissions or installation requirements.
- Keep PRs focused. Describe the problem, resulting behavior, validation and remaining limitations. Report which checks actually ran.
- When delivering an APK, provide its download link and the relevant PR/commit. For documentation-only work, link the changed document and PR.
