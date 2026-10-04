# Droidmap

A standalone Android app for private IPv4 device discovery, TCP connect scans and evidence-based device identification. It runs on the phone without a Linux backend, root, Nmap, Nuclei, Metasploit or a model runtime. This app was extracted from [Netmap](https://github.com/hebermattos/Netmap), and remains independent of its .NET vulnerability pipeline. Version 0.6.1 adds a compact interface with expandable device cards and an Options menu for scan settings, Wi-Fi target selection, history, reanalysis and exports.

## Features

- A black-and-white radar/network launcher icon, with adaptive masks on Android 8+ and themed monochrome icons on Android 13+.

- Scan a single private IPv4 address or a /24–/32 network.
- Suggest the connected Wi-Fi IPv4 network (larger subnets are reduced to the local /24).
- Edit ports as comma-separated values or ranges, and set a 100–3000 ms connection timeout.
- View responding devices and open ports grouped by IP.
- Collect mDNS service names/TXT model hints, SSDP/UPnP names/manufacturer/model, HTTP titles/server headers, passive SSH/FTP/Telnet banners and NetBIOS node-status names.
- Show NetBIOS-reported MAC addresses when available; label device types as probable and preserve each observation source.
- Track completed connections, cancel scans and export full or partial results as JSON.
- Choose Fast or Complete mode. Complete expands the default port preset, retries timed-out TCP connections once with a doubled timeout and extends identification/discovery budgets. Custom port selections are preserved when switching modes.
- Verify advertised TCP endpoints, including ports outside the selected list; use HTTP announcements to read nonstandard HTTP ports.
- Bound scanning to 32 concurrent connections, 256 addresses and 256 distinct selected ports, plus at most 16 announced endpoints per device.

## Build and install

Requirements: JDK 17, Android SDK platform 35 and build tools 35.0.0. The Gradle wrapper uses 8.11.1; Android Gradle Plugin is pinned to 8.9.2.

Open this directory in Android Studio, allow Gradle sync, and run the app on an Android 8.0+ device. Alternatively, set `ANDROID_HOME` to your SDK path (or create `local.properties` with `sdk.dir=...`) and run:

```bash
cd Droidmap
./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

On Windows, use `gradlew.bat :app:assembleDebug :app:lintDebug`.

The Android CI workflow can also be run manually on the feature branch. It builds and uploads the `droidmap-debug` APK artifact. Debug builds are suitable for local testing; store distribution requires your own release signing configuration.

## Use

1. Connect your phone to the local Wi-Fi network.
2. Enter a private IP address or network, or open **Options → Use Wi-Fi network**.
3. Open **Options → Scan settings** to choose Fast/Complete mode, TCP ports, timeout and adaptive scanning. Tap **Save** to apply; settings persist between launches. Cancel discards edits.
4. Tap **Start scan**. The same button becomes **Cancel scan** while running; cancellation retains partial results.
5. Tap a device card to expand or collapse details directly in the list. Details group open ports, identity, identification reasons and evidence by source; values can be selected and copied. Expanded devices stay expanded when rotating a saved result. Open **Options → Full report** for the detailed scan and history comparison.
6. Use **Options → History**, **Reanalyze a device** or **Export JSON**. Export uses Android's document picker and requires no broad storage permission.

The main screen keeps the target, settings summary and one scan button above the results. Options that cannot run during a scan are disabled. The black background and white text are preserved.

## What the results mean

- `OPEN`: a TCP connection was established.
- `CLOSED`: the OS reported an explicit connection refusal; this counts as evidence of a responsive IP.
- `NO_RESPONSE`: the connection timed out; this does not distinguish filtering from an offline device.
- `ERROR`: another connection failure (including missing permission or routing problems); this does not prove the device is online.

TCP discovery tests each selected port on each target. Identification additionally queries mDNS services, sends one SSDP multicast search, reads same-sender UPnP descriptions and queries NetBIOS node status (UDP 137). Devices advertising a matching service can appear even when selected TCP ports are silent. Devices with only UDP services or silent firewalls can be missed. Ports are numbers, not identified services or confirmed vulnerabilities. This version does not perform ICMP/ARP discovery, exhaustive UDP scanning, authentication or exploitation. It has no MAC/OUI vendor database and cannot obtain every device MAC address. It accepts only RFC 1918 private IPv4 addresses.

Scanning uses the OS routing table. Wi-Fi client isolation, VPN routes, mobile-data routing, or local-network restrictions can prevent responses. The app targets SDK 35 with `INTERNET` and `ACCESS_NETWORK_STATE` permissions; retargeting to SDK 37+ requires implementing the local network runtime permission described in [Android's local-network documentation](https://developer.android.com/privacy-and-security/local-network-permission).

Scans stop when the Activity is destroyed (including screen rotation). Small completed reports survive screen recreation; large reports should be exported first. Reports are not persisted between app launches. The app does not upload results. Results are self-reported observations, not authenticated hardware identities. Port numbers alone never determine manufacturer/model.

## Tests

The scanner has a plain Java test suite covering private-target validation, CIDR boundaries, port limits, real open/refused TCP connections, result ordering, concurrency and cancellation:

```bash
bash android/tests/run.sh
```

The identification suite additionally tests target filtering, evidence bounds/deduplication, HTTP/UPnP parsing, description URL restrictions, NetBIOS packet validation and real socket reads. The tests run on a development machine with JDK 17; loopback is used only by the test harness and is not accepted in the app target field. Android CI additionally compiles the APK and runs Android lint. Physical-device validation is still required for Wi-Fi routing, screen layout and document export.

## Identification details and limits

- mDNS uses Android NSD to browse HTTP/HTTPS, Google Cast, AirPlay/RAOP, IPP/IPPS/printers, SMB, workstations, Android TV and ADB TLS services. It resolves serially for compatibility and stops after six seconds in Fast mode or twelve in Complete mode. The identification phase waits for this bounded discovery window before taking its endpoint snapshot. Out-of-target resolved addresses are ignored. Service names are advertised labels, not guaranteed hostnames.
- SSDP listens for at most three seconds in Fast mode or five seconds in Complete mode / 512 packets. UPnP descriptions are requested only from a literal HTTP address matching the reply sender. No redirects or external description hosts are followed, and entity-bearing XML is rejected. Reported fields include friendly name, manufacturer, model name/number, device type and UDN when present.
- NetBIOS sends one node-status request per target with a 250 ms receive timeout and validates sender, transaction ID and record bounds. Names/workgroups and nonzero MACs are included when reported; this is not a universal MAC discovery method.
- TCP fingerprint reads are capped at four per responsive host in Fast mode or eight in Complete mode. Passive banners are read from selected open ports 21/22/23. HTTP requests use selected open ports 80/8000/8080/8888 or verified nonstandard ports explicitly advertised as `_http._tcp` and collect page titles and server headers. HTTPS is not fingerprinted and self-signed TLS validation is not bypassed.
- Identification uses eight workers, a twenty-second identification budget in Fast mode or sixty seconds in Complete mode, read deadlines and byte limits. Cancellation closes active sockets. Results retain partial-identification notices if the budget is reached. Discovery failures are best effort and do not discard TCP results.
- A Cast service means a Cast receiver capability; it does not establish a Chromecast hardware model. Printer/AirPlay/media-server categories are similarly marked **probable**. Friendly names, manufacturers and models are labeled **reported**. Unknown devices remain unknown.

JSON schema version 3 preserves the original TCP checks and adds `devices` with reported name/manufacturer/model/MAC, probable type, confidence explanation and sourced evidence, plus `identificationNotices`, mode/retry metadata, per-check attempt/final-timeout fields and a separate `advertisedEndpointChecks` array. MAC/vendor identification for silent devices remains unavailable. Physical-device tests are required for Android NSD callbacks and real Wi-Fi multicast behavior.

## Scan profiles (0.3.0)

| Setting | Fast | Complete |
| --- | --- | --- |
| Default selected TCP ports | 19 | 39 |
| Retries after a TCP timeout | None | One |
| Retry timeout | Not applicable | Twice the entered timeout, capped at 3000 ms |
| mDNS window | 6 seconds | 12 seconds |
| SSDP receive window | 3 seconds | 5 seconds |
| Identification budget | 20 seconds | 60 seconds |
| Fingerprint read cap per host | 4 | 8 |

Complete mode can take substantially longer, especially when many devices silently drop connections. Only `NO_RESPONSE` connections are retried; open ports, explicit refusals and routing/permission errors are not retried. Progress counts unique selected host/port checks, not individual attempts. Entered timeout and custom ports remain authoritative.

Announcements are stored as typed, target-filtered endpoints, deduplicated by IP/port and capped at sixteen per host. Each endpoint is checked by TCP connection before it is treated as open. Existing conclusive selected-port checks are reused; selected timeouts can be rechecked during identification. A UDP advertisement is not converted into a TCP check. HTTP fingerprinting on nonstandard ports requires an explicit HTTP service advertisement; HTTPS and printer announcements are never used to send guessed plaintext HTTP requests. SSDP description URLs remain restricted to the reply sender.

The screen merges confirmed additional ports into each device's open-port inventory. JSON keeps initial selected-port checks and advertised-endpoint checks separate, preserving both the original timeout and any later verification. Discovery and identification budgets are separate from the selected-port scan duration; they do not impose a total scan deadline.

## Reverse DNS (dnsjava)

dnsjava 3.6.5 builds and validates PTR queries for independently responding or announced scan targets. Queries use up to two private IPv4 DNS servers on a matching Wi-Fi network. Both UDP and TCP sockets are bound to that network; no public or cellular resolver fallback is used. Each server shares a total budget of 600 ms (Fast) or 1200 ms (Complete), including alias resolution and TCP fallback, within the existing identification deadline.

Truncated UDP replies can be retried over TCP. Resolution is capped at five queries per server and four CNAME links per response, with cycle detection. The in-memory LRU cache holds at most 512 positive answers, separates Wi-Fi network handles and DNS servers, and expires at the minimum answer/alias TTL capped at one hour. TTL zero and negative replies are not cached. Cancellation closes active sockets.

Names appear as fallback reported names and as `dnsHostname` with DNS source evidence in JSON. Cached PTR names do not establish current reachability or manufacturer. Networks without matching private IPv4 Wi-Fi DNS show a skip notice.

## Identification and adaptive scanning

- Eighteen mDNS service types cover HTTP, printing, SMB, Cast, AirPlay, Android TV, ADB, HomeKit, Spotify, DAAP, MQTT, VNC and scanners. Discovery rotates batches of at most six active requests for older Android limits, within the mode window. TXT fields retain advertised names, model hints, manufacturer, UUID, OS version, location and printer resource paths.
- Advertised plaintext IPP endpoints, or selected open TCP/631 endpoints with no conflicting advertisement, receive only **Get-Printer-Attributes**. No print jobs or configuration changes are sent. IPPS is never queried with plaintext. Responses require HTTP 200/application-ipp, matching request ID, successful IPP status, complete bounded attributes and valid HTTP framing. Printer resource paths are constrained to the target device.
- Manufacturer suggestions use explicit brand tokens in service metadata/banners. Conflicting reported manufacturers suppress suggestions. Repeated matching identity values across protocol families are labeled **Corroborated, unverified**; this is agreement, not authenticated identity. DNS names alone do not infer a manufacturer or device type. JSON schema 4 includes reasons, suggestions and the adaptive setting.
- Optional **Adaptive scan** first probes one selected port on every target, then prioritizes responders. It starts at 16 concurrent probes, adjusts between 4 and 32 using 32-result windows, and may increase subsequent timeouts using observed response latency, capped at 3000 ms. It never shortens the entered timeout or skips any selected host/port. Disable it for fixed concurrency/timeouts. Complete-mode retries remain bounded as before.

## Reanalysis and history

**Reanalyze IP** selects an observed device and starts a Complete scan of that single IP with the Complete port preset. The app stores up to 20 compact completed-scan summaries in private internal storage, capped at 4 MiB. History includes observed responders, names/models/types and open ports, and survives app restarts. It compares only the same normalized target range and selected-port list. Cancelled or incomplete TCP scans do not become comparison baselines. Missing devices/ports are labeled **not observed**, not offline or definitively closed. Identification budgets and filtering may affect observations. JSON exports include `historyComparison`.

**History** opens previous summaries. Summaries do not preserve every raw connection result; export JSON after a scan for the full evidence. History remains local to each app installation. Uninstalling an app removes its private history.

## Tests

Run `bash tests/run.sh` for scanner/identification regression checks and `./gradlew :app:testDebugUnitTest` for DNS validation, aliases, scoped cache/TTL expiry/TCP fallback, IPP framing, manufacturer rules, adaptive completeness/concurrency and history persistence/comparisons.

## APK update signature conflicts

Android updates require the same application ID and signing key as the installed APK. A freshly generated debug key cannot update an older debug build. Keep the signing keystore across builds; do not commit private keys to the repository.

For testing while preserving an older installation, build a separate app:

```bash
./gradlew :app:assembleDebug :app:lintDebug -PsideBySideInstall=true
```

This uses `com.netmap.android.dns` and the launcher label **Netmap Lite DNS**. It installs alongside the original app and does not migrate its data. Future updates to this separate app still require its original signing key.

## Repeatable local APK updates

The delivered APK uses the separate `com.netmap.android.dns` package and the same saved debug signing key as version 0.4.1. Keep the **Netmap-Debug-Signing-Backup.zip** delivered with the APK. Restore its `netmap-debug.keystore` into `.signing/`, then run:

```bash
cd Droidmap
bash build-apk.sh --no-daemon
```

The script requires the saved key and checks its certificate against the delivered APK and refuses to create a replacement key silently. `NETMAP_DEBUG_KEYSTORE` can point to the saved file elsewhere. Keys are ignored by Git and never committed. Ordinary CI builds use an ephemeral debug key for testing and are not update-compatible with the delivered APK. Release/store distribution still requires a separate release-signing configuration.

## Migration and installed-app compatibility

The Android project now lives at the repository root. Java namespace, application IDs, version 0.5.0 and signing configuration are preserved, so moving repositories does not reset installed-app data or change APK update requirements. The launcher retains its Netmap Lite name for compatibility. Signing backups remain outside Git.
