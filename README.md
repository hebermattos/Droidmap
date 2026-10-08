# Droidmap

A standalone Android app for private IPv4 and observed Wi-Fi IPv6 discovery, TCP connect scans and evidence-based device identification. It runs on the phone without a Linux backend or root, with optional packaged ARM64 Nmap enrichment. This app was extracted from [Netmap](https://github.com/hebermattos/Netmap), and remains independent of its .NET vulnerability pipeline. Version 0.10.1 uses a 200 ms default connection timeout, overlaps SSDP discovery with TCP scanning, and supports user-started background scans and a compact interface with expandable device cards and an Options menu for scan settings, Wi-Fi target selection, history, reanalysis and exports.

## Code ownership

- `MainActivity` coordinates lifecycle, user actions and service snapshots. `ScanSettings`, `ScanSettingsStore` and `ScanSettingsDialog` own validated options, preference migration and editing.
- `DeviceResultsRenderer`, `ScanHistoryDialog` and `ReportExporter` own device cards, history presentation and export state/I/O. `ExportRequest` pins exports to the selected scan across Activity recreation.
- `DeviceIdentifier` schedules discovery/identification and verifies advertised endpoints. `SsdpDiscovery` and the HTTP, TLS, SMB, RTSP, IPP, NetBIOS, UPnP and banner probes own protocol operations. `ProbeContext` shares deadline, read bounds and active socket ownership with cancellation.
- `DeviceProfile` makes typed decisions using `DeviceConfidence`; `IdentificationStatus` expresses completion. JSON and text reports retain their existing labels and schema version 5.

## Features

- The screen header displays Droidmap and the installed app version, sourced from the build configuration.

- A black-and-white radar/network launcher icon, with adaptive masks on Android 8+ and themed monochrome icons on Android 13+.

- Scan a single private IPv4 address or a /24–/32 network.
- Select **Options → Scan all Wi-Fi IPs** to scan every usable IPv4 address on the connected private Wi-Fi subnet. The selected target and address count appear before you tap **Start scan**. Network and broadcast addresses are excluded for /24–/30; /31 and /32 retain all addresses. Every selected IP/port is checked, including silent hosts.
- The all-IP option keeps the actual subnet prefix (/24–/32) and rejects larger networks with an explicit message instead of silently truncating them. **Use Wi-Fi network** remains a shortcut to a bounded range (larger subnets use the local /24). IPv6 discovery remains enabled for observed local addresses; IPv6 subnets are not enumerated.
- Edit ports as comma-separated values or ranges, and set a 100–3000 ms connection timeout.
- View responding devices and open ports grouped by IP.
- Collect mDNS service names/TXT model hints, SSDP/UPnP names/manufacturer/model, HTTP titles/server headers, passive SSH/FTP/Telnet banners and NetBIOS node-status names.
- Show MAC addresses from NetBIOS, IPv4/IPv6 neighbor observations and Nmap XML when available, preserving each source. Expand a device card to see **MAC addresses**, also included in the full report and JSON. Locally administered addresses are labeled as possibly randomized; no factory identity or vendor is inferred from them.
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
2. Enter a private IP address or network, or open **Options → Use Wi-Fi network**. To select the entire connected Wi-Fi subnet, choose **Options → Scan all Wi-Fi IPs**, review the address count, then tap **Start scan**.
3. Open **Options → Scan settings** to choose Fast/Complete mode, TCP ports, timeout and adaptive scanning. The default timeout is **200 ms**; a one-time upgrade changes a saved legacy 500 ms value to 200 ms, preserving other customized values. Later explicit edits, including 500 ms, persist. Tap **Save** to apply; Cancel discards edits. Increase the timeout if your Wi-Fi or devices respond slowly.
4. Tap **Start scan**. The same button becomes **Cancel scan** while running; cancellation retains partial results.
5. Tap a device card to expand or collapse details directly in the list. Details group open ports, identity, identification reasons and evidence by source; values can be selected and copied. Expanded devices stay expanded when rotating a saved result. Open **Options → Full report** for the detailed scan and history comparison.
6. Use **Options → History**, **Reanalyze a device** or **Export JSON**. Export uses Android's document picker and requires no broad storage permission.

Devices and confirmed open ports appear during scanning; identification details update progressively, labeled as devices found so far until the full report is complete. Previews are limited to approximately one update per second and do not replace the durable final report. The main screen keeps the target, settings summary and one scan button above the results. Options that cannot run during a scan are disabled. The black background and white text are preserved.

## Background scans

Start a scan while the app is visible. A `connectedDevice` foreground service owns TCP scanning, discovery and identification, so switching apps, rotating the screen or dismissing the activity from Recents does not cancel it. The notification shows progress, opens the app and offers **Cancel**. Only one scan runs at a time. Notifications are requested on Android 13+; denying permission still allows the service to run, but hides drawer progress/cancellation (in-app controls remain available).

Completed and normally cancelled scans save their full JSON and formatted report atomically in private app storage. Returning to the app restores the current progress or latest result, including reports too large for an activity Bundle. The latest-result file is bounded to 32 MiB; history remains separately bounded. If saving fails, the app reports it and keeps the current result in memory for export.

The service does not restart scans after process termination, force-stop or reboot. A persisted running marker is restored as interrupted, with no completed report. Force-stop and manufacturer battery restrictions can still interrupt execution; screen-off/Doze networking is not guaranteed. No battery-optimization exemption or indefinite wake lock is requested. The scan begins from a visible user action, never automatically from boot or background scheduling.

## What the results mean

- `OPEN`: a TCP connection was established.
- `CLOSED`: the OS reported an explicit connection refusal; this counts as evidence of a responsive IP.
- `NO_RESPONSE`: the connection timed out; this does not distinguish filtering from an offline device.
- `ERROR`: another connection failure (including missing permission or routing problems); this does not prove the device is online.

TCP discovery tests each selected port on each target. Identification additionally queries mDNS services, sends one SSDP multicast search, reads same-sender UPnP descriptions and queries NetBIOS node status (UDP 137). Devices advertising a matching service can appear even when selected TCP ports are silent. Devices with only UDP services or silent firewalls can be missed. Ports are numbers, not identified services or confirmed vulnerabilities. This version does not perform ICMP/ARP discovery, exhaustive IPv6 prefix sweeps, exhaustive UDP scanning, authentication or exploitation. It has no MAC/OUI vendor database and cannot obtain every device MAC address. After TCP scanning, it attempts a bounded, one-second IPv4 neighbor-table read on the captured Wi-Fi interface. Only selected on-link hosts with valid unicast MACs are accepted; cached entries do not prove current reachability. Android 8–9 can fall back to completed Ethernet entries from `/proc/net/arp`; Android 10+ does not attempt that restricted file. Access failures are explained in report notices and do not stop the scan. MAC values of all zeros, multicast/broadcast addresses and the Android `02:00:00:00:00:00` placeholder are excluded. Missing MACs display **Unavailable — not observed or access restricted**. Nmap MAC observations require an address explicitly present in its XML; TCP connect mode does not guarantee MAC discovery. IPv6 neighbor MAC observations, when Android permits them, are separately labeled as cached link-layer information. IPv4 targets are restricted to RFC 1918 addresses. IPv6 targets must be unicast addresses on the connected Wi-Fi link; global IPv6 literals are accepted only after matching a Wi-Fi prefix.

Scanning uses the OS routing table. Wi-Fi client isolation, VPN routes, mobile-data routing, or local-network restrictions can prevent responses. The app targets SDK 35 with `INTERNET` and `ACCESS_NETWORK_STATE` permissions; retargeting to SDK 37+ requires implementing the local network runtime permission described in [Android's local-network documentation](https://developer.android.com/privacy-and-security/local-network-permission).

User-started scans belong to the foreground service and survive Activity recreation, including screen rotation. Completed and normally cancelled reports are persisted atomically between app launches. The app does not upload results. Results are self-reported observations, not authenticated hardware identities. Port numbers alone never determine manufacturer/model.

## Tests

The scanner has a plain Java test suite covering private-target validation, CIDR boundaries, port limits, real open/refused TCP connections, result ordering, concurrency and cancellation:

```bash
bash tests/run.sh
```

The Gradle unit suite also checks extracted probe routing, HTTP evidence/socket cleanup, typed confidence serialization, immutable settings and run-scoped export restoration.

The identification suite additionally tests target filtering, evidence bounds/deduplication, HTTP/UPnP parsing, description URL restrictions, NetBIOS packet validation and real socket reads. The tests run on a development machine with JDK 17; loopback is used only by the test harness and is not accepted in the app target field. Android CI additionally compiles the APK and runs Android lint. Physical-device validation is still required for Wi-Fi routing, screen layout and document export.

## Identification details and limits

- mDNS uses Android NSD to browse HTTP/HTTPS, Google Cast, AirPlay/RAOP, IPP/IPPS/printers, SMB, workstations, Android TV and ADB TLS services. It resolves serially for compatibility and stops after six seconds in Fast mode or twelve in Complete mode. The identification phase waits for this bounded discovery window before taking its endpoint snapshot. Out-of-target resolved addresses are ignored. Service names are advertised labels, not guaranteed hostnames.
- SSDP starts alongside TCP scanning and its completed receive window is reused by identification. It listens for at most three seconds in Fast mode or five seconds in Complete mode / 512 packets. UPnP descriptions are requested only from a literal HTTP address matching the reply sender. No redirects or external description hosts are followed, and entity-bearing XML is rejected. Reported fields include friendly name, manufacturer, model name/number, device type and UDN when present.
- NetBIOS sends one node-status request per target with a 250 ms receive timeout and validates sender, transaction ID and record bounds. Names/workgroups and nonzero MACs are included when reported; this is not a universal MAC discovery method.
- TCP fingerprint reads are capped at four per responsive host in Fast mode or eight in Complete mode. Passive banners are read from selected open ports 21/22/23. HTTP requests use selected open ports 80/8000/8080/8888 or verified nonstandard ports explicitly advertised as `_http._tcp` and collect page titles and server headers. HTTPS/TLS, RTSP and SMB have bounded read-only fingerprints as described below. Self-signed TLS validation is not bypassed.
- Identification uses eight workers, a twenty-second identification budget in Fast mode or sixty seconds in Complete mode, read deadlines and byte limits. Cancellation closes active sockets. Results retain partial-identification notices if the budget is reached. Discovery failures are best effort and do not discard TCP results.
- A Cast service means a Cast receiver capability; it does not establish a Chromecast hardware model. Printer/AirPlay/media-server categories are similarly marked **probable**. Friendly names, manufacturers and models are labeled **reported**. Unknown devices remain unknown.

JSON schema version 5 preserves the original TCP checks and adds `devices` with reported name/manufacturer/model/MAC, probable type, confidence explanation and sourced evidence, plus `identificationNotices`, mode/retry metadata, per-check attempt/final-timeout fields and a separate `advertisedEndpointChecks` array. The additive `macAddresses` array preserves MAC address, source and administration type without replacing the existing NetBIOS `reportedMac` field. MAC/vendor identification for silent devices is not guaranteed. Physical-device tests are required for Android NSD callbacks and real Wi-Fi multicast behavior.

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

dnsjava 3.6.5 builds and validates PTR queries for independently responding or announced scan targets. Queries use up to two local IPv4 or link-local/ULA IPv6 DNS servers on a matching Wi-Fi network. Both UDP and TCP sockets are bound to that network; no public or cellular resolver fallback is used. Each server shares a total budget of 600 ms (Fast) or 1200 ms (Complete), including alias resolution and TCP fallback, within the existing identification deadline.

Truncated UDP replies can be retried over TCP. Resolution is capped at five queries per server and four CNAME links per response, with cycle detection. The in-memory LRU cache holds at most 512 positive answers, separates Wi-Fi network handles and DNS servers, and expires at the minimum answer/alias TTL capped at one hour. TTL zero and negative replies are not cached. Cancellation closes active sockets.

Names appear as fallback reported names and as `dnsHostname` with DNS source evidence in JSON. Cached PTR names do not establish current reachability or manufacturer. Networks without matching local Wi-Fi DNS show a skip notice.

## Identification and adaptive scanning

Identification prioritizes TCP responders and independently announced devices, then still checks silent targets for NetBIOS evidence. An indexed responder set avoids repeatedly traversing all TCP checks for each IP. SSDP has one bounded discovery worker, starts before TCP checks and is joined within the identification budget; cancellation closes its socket and interrupts its worker.

- Nineteen mDNS service types cover HTTP, printing, SMB, Cast, AirPlay, Android TV, ADB, HomeKit, Spotify, DAAP, MQTT, VNC, scanners and RTSP. Discovery rotates batches of at most six active requests for older Android limits, within the mode window. TXT fields retain advertised names, model hints, manufacturer, UUID, OS version, location and printer resource paths.
- Advertised plaintext IPP endpoints, or selected open TCP/631 endpoints with no conflicting advertisement, receive only **Get-Printer-Attributes**. No print jobs or configuration changes are sent. IPPS is never queried with plaintext. Responses require HTTP 200/application-ipp, matching request ID, successful IPP status, complete bounded attributes and valid HTTP framing. Printer resource paths are constrained to the target device.
- Manufacturer suggestions use explicit brand tokens in service metadata/banners. Conflicting reported manufacturers suppress suggestions. Repeated matching values for the same identity field across protocol families are labeled **Corroborated, unverified**; this is agreement, not authenticated identity. DNS names alone do not infer a manufacturer or device type. JSON schema 5 includes reasons, suggestions and the adaptive setting.
- Optional **Adaptive scan** first probes one selected port on every target, then prioritizes responders. It starts at 32 concurrent probes, adjusts between 8 and 32 using 32-result windows based on connection errors or latency of confirmed responses (silence alone does not reduce concurrency), and may increase subsequent timeouts using observed response latency, capped at 3000 ms. It never shortens the entered timeout or skips any selected host/port. Disable it for fixed concurrency/timeouts. Complete-mode retries remain bounded as before.

## Reanalysis and history

**Reanalyze IP** selects an observed device and starts a Complete scan of that single IP with the Complete port preset. The app stores up to 20 compact completed-scan summaries in private internal storage, capped at 4 MiB. History includes observed responders, names/models/types and open ports, and survives app restarts. It compares only matching Wi-Fi session scope, normalized target range, selected ports, mode, timeout and adaptive setting. Cancelled, incomplete TCP or partial-identification scans do not become comparison baselines. Missing devices/ports are labeled **not observed**, not offline or definitively closed. Identification budgets and filtering may affect observations. JSON exports include `historyComparison`.

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

## Evidence quality and protocol analysis (0.8.0)

- mDNS TXT fields retain their meaning: OS versions, products and service-specific model attributes are separate.
- Model, manufacturer and device type have separate confidence labels. Conflicting models are withheld; cross-field agreement does not increase confidence.
- Read-only fingerprints prioritize IPP and advertised services over generic banners. NetBIOS still checks silent targets after higher-value reads. The TCP default remains 200 ms; identification has independent bounded deadlines.
- HTTPS/TLS uses the platform trust store and verifies the target IP. Valid handshakes report TLS version, cipher and certificate metadata. Self-signed, untrusted or IP-mismatched certificates remain validation failures; no trust bypass, authentication or redirects are used. IPPS receives only a TLS handshake.
- RTSP uses `OPTIONS *` with response sequence validation. It does not authenticate, request media or start streaming. RTSP advertisements on nonstandard TCP ports are supported.
- UPnP description bodies use bounded HTTP framing, including chunked responses with XML content types.
- Expanded device details and JSON include confidence per identity field and evidence-based findings. Findings do not assert vulnerabilities from port numbers or version strings.
- JSON schema 5 includes TCP completion, identification status and network scope. Time-limited identification is visibly partial, even when all TCP checks completed.
- History baselines require complete identification and matching target, ports, mode, timeout, adaptive setting and Wi-Fi session scope. Missing network identity or a network change skips comparison. Scopes include the Android boot counter and network handle: reconnecting or rebooting conservatively starts a new baseline. Existing unscoped entries remain readable but are not reused for comparison.

SMB uses only unauthenticated SMB2 NEGOTIATE on port 445 or announced SMB TCP endpoints. It reports the negotiated dialect (2.0.2 through 3.0.2) and signing advertisement, without session setup, share access or file operations. This does not enumerate every supported dialect or test SMB 3.1.1. MQTT-specific fingerprints remain outside this release.


## Nmap enrichment (ARM64)

The separate Nmap setting defaults to enabled in Fast mode. CI packages the checksum-pinned ARM64 Android Nmap archive and its databases/NSE files. Enrichment uses TCP connect scanning (`-sT`) without root. IPv6 commands include `-6`; link-local targets select the Wi-Fi interface with `-e`. Nmap DNS is disabled (`-n`) so PTR lookup stays in Droidmap's Wi-Fi-bound local DNS path. Service detection targets only verified-open TCP ports from the native scan and advertised endpoint checks, capped at 256 ports per host. Both Fast and Complete attempt every found device with at least one verified-open TCP port. Each Nmap service scan targets only that device’s open ports from initial TCP checks and verified advertised endpoints. Silent/closed checks and unverified announcements are excluded. There is no Nmap host-count cap; duplicate hosts/ports are removed and targets run sequentially. Cancellation can stop remaining targets. Safe vulnerability checks retain their separate evidence section and operate only on Nmap-confirmed open ports. Cancelling stops the active process. Missing ARM64 support or data records a notice and preserves native scan results.

## IPv6 information collection (0.9.1)

- Android 14+ tracks mDNS service updates with `registerServiceInfoCallback` and processes multiple advertised host addresses through `getHostAddresses()`. Android 8–13 retains serial legacy resolution; complete multi-address discovery is not guaranteed there. Discovery is bound to the matching Wi-Fi network on Android 13+.
- Additional IPv6 addresses are accepted only on the captured Wi-Fi link, with interface scopes preserved for link-local addresses. Global unicast addresses must match a local Wi-Fi prefix. A manually entered unscoped link-local target receives the matching Wi-Fi scope automatically.
- Discovery is bounded to 256 additional IPv6 addresses, 128 service instances, 32 tracked service callbacks and 16 addresses per service update. The existing discovery and identification deadlines remain authoritative. Reaching a tracking limit marks discovery partial.
- Discovered peers enter the identification queue and advertised-port checks, local DNS PTR lookup and optional Nmap enrichment. They do not imply an exhaustive selected-port sweep of an IPv6 prefix. Observations, advertised checks and Nmap evidence remain separately sourced in JSON.
- **IPv6 network** in each expanded device card displays address type, interface, related service addresses and neighbor metadata when available. The phone's own addresses are explicitly labeled **This phone**. Addresses belonging to the same advertised service are related observations, not proof of a shared physical device.
- Neighbor-table collection runs on the scan worker, has a one-second process deadline and is best effort. Cached neighbor state and MAC are shown separately; neither establishes current reachability or a verified hardware identity. Android can deny neighbor access, in which case the report explains that mDNS remains active. Failed/incomplete neighbor entries are ignored.
- Compressed and expanded IPv6 representations share one evidence key. Nmap XML lacking a link-local zone maps only to an unambiguous existing scoped target. HTTP and IPP use bracketed IPv6 authorities. NetBIOS node-status probes are skipped for IPv6.

Silent devices, Wi-Fi client isolation and Android restrictions can still prevent identification. A /64 is not enumerated and finding every IPv6 address is not guaranteed. Names, model, manufacturer, firmware and serial values appear only when a responding service reports them. Run `bash tests/run.sh` for the MAC and IPv6 regression suites as well as the existing scanner/identification checks.


### Nmap command templates

The app reads `app/src/main/assets/nmap-command-templates.json` at the start of each Nmap enrichment run. Edit this JSON and rebuild the APK to change command arguments, IPv6 argument groups, environment variables, service/vulnerability process deadlines, output limits. The packaged file is read directly; it is not copied into persistent app storage and no hardcoded command fallback is used. Missing or malformed templates produce an identification notice and skip Nmap while preserving native scanning.

`profiles.serviceDetection.argv` and `profiles.vulnerabilityDetection.argv` are argument arrays, not shell command strings. Runtime bindings substitute `{host}`, `{ports}` or `{openPorts}`, `{timeoutMs}`, `{interface}`, `{binary}`, `{dataDir}` and `{libraryDir}`. The host remains a validated single local IP; the IPv6 zone becomes a separate interface argument. Vulnerability scans are skipped when Nmap found no open ports. The existing confirmed-port selection, Wi-Fi scope, cancellation and XML parsing behavior remain in code; descriptive JSON fields such as `requires`, `skipWhen`, `selection.order` and `argumentOrder` document that behavior rather than execute expressions.

The JSON specifies process deadlines from 1–300 seconds, output read deadlines from 1–30 seconds and output caps up to 1 MiB. The connection timeout range stays within 100–3000 ms. The template has no Fast/Complete host-count limit. To use a changed configuration on an installed phone, install the rebuilt APK; runtime file import/editing is not included. Plain Java checks now require Python 3 to generate test input from the actual packaged JSON. Gradle unit tests load that same asset to validate JSON parsing and changed command behavior.


### Vulnerability checks by target port and service

The vulnerability profile runs `-sT -sV --version-light -Pn` on Nmap-confirmed open TCP ports only, followed by the configured safe-category vulnerability NSE expression. Nmap uses each script's port/service rules to decide applicability; scripts are not forced on unrelated services. Service detection runs in this second process as well, so an HTTP service on a nonstandard port can be recognized before NSE evaluates its rules. Detection and script execution remain subject to the configured host/script deadlines and the packaged script database; not every port or service has a matching check.

Expanded **Nmap vulnerabilities** details show target ports, selection behavior, per-port service metadata and script output. Host-script results (such as applicable SMB checks) are retained as **host-level** rather than attributed to an unverified port. Parsing accepts per-port results only for the selected TCP ports still reported open; closed, UDP, unselected and off-target results are ignored. Host-level output is retained only when the response includes an eligible open target TCP port. A command finishing without findings does not establish that scripts ran for every service or that a device is free of vulnerabilities. Existing exclusions for brute force, DoS, intrusive and exploit categories remain in the JSON.


Nmap target selection includes every found device with an OPEN TCP check in the validated scan plan or verified advertised endpoint checks. IPv4 and admitted IPv6 addresses follow the same rule. A discovered address or service announcement alone is insufficient; its TCP endpoint must have been verified open. Per-target failures do not stop subsequent devices. Reports show attempted/total eligible devices and cancellation notices. Vulnerability scripts continue to run only on these ports still confirmed open by Nmap.

### Nmap execution diagnostics

Live scan details show the running profile, then its completed or failed status. Expand **Nmap diagnostics** in a device card and tap **View full technical log** for the service or vulnerability profile to open a scrollable, selectable response. The response includes the exact argv, profile, exit code (when available), elapsed time, execution error, full captured XML stdout and separate stderr. Warnings no longer corrupt the XML parser. Launch failures, nonzero exits, timeouts and cancellations retain their diagnostics; a successful process exit does not by itself establish successful XML parsing or the absence of vulnerabilities. The existing scan status reports parsing errors.

Diagnostics are read and written off the UI thread and survive activity recreation and app restart. Output is captured up to the JSON-configured byte limit **per stream**; exceeding it fails enrichment and explicitly marks the captured output as truncated. Files are limited to 3 MiB each, 32 MiB per scan and 64 MiB total, retaining at most eight scan directories. Storage failures are visible; older scan output is removed when the total budget is reached. Saved JSON contains run-scoped local output references, not the raw file contents; exported JSON does not transfer those local files to another device. Older reports cannot display output captured before this feature.

Version 0.9.8 fixes Nmap XML processing on Android: the parser no longer requests unsupported desktop Xerces features. The standard bare Nmap DOCTYPE is removed; DTD/entity declarations are rejected before parsing and external entity resolution is blocked. Service and vulnerability XML use the same parser. A completed process with invalid XML is explicitly reported as an XML processing failure. When no verified-open TCP ports were found, the report explains that Nmap was skipped.

Version 0.9.9 packages and installs `nse_main.lua` together with all runtime databases, scripts and NSE libraries. Both command profiles explicitly use `--datadir` to select the installed files. NSE initialization is required even for service detection (`-sV`). CI validates the runtime file manifest before building and checks the same files inside the final APK, failing on missing or empty files.

## Reading reports

Version 0.10.0 starts with scan completion/partial status, device and unique open TCP endpoint counts, alert/failure counts, and Nmap execution totals. Filters show All, Open ports, Alerts or Failures without changing scan/export data. Device cards keep IP/name, probable type, open ports, Nmap status and vulnerability status visible. Expand a card for a port/service/product table, finding scope/evidence/suggested action, identification, diagnostics and additional sourced metadata. Alerts distinguish explicit reported vulnerability evidence from warnings and inconclusive or informational results; no finding is automatically authenticated or confirmed. Missing results are labeled Not executed, never interpreted as a clean vulnerability assessment. Technical logs are opened separately from Nmap diagnostics. Full report follows the same summary/device grouping with real line breaks; JSON keeps the existing complete evidence and checks.
