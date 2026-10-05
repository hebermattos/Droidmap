#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
classes_dir="$(mktemp -d)"
trap 'rm -rf "$classes_dir"' EXIT
sources=(
  "$project_dir/app/src/main/java/com/netmap/android/ScanPlan.java"
  "$project_dir/app/src/main/java/com/netmap/android/IpAddresses.java"
  "$project_dir/app/src/main/java/com/netmap/android/TcpScanner.java"
  "$project_dir/app/src/main/java/com/netmap/android/AdaptivePolicy.java"
  "$project_dir/app/src/main/java/com/netmap/android/DeviceEvidence.java"
  "$project_dir/app/src/main/java/com/netmap/android/DeviceIdentifier.java"
  "$project_dir/app/src/main/java/com/netmap/android/NetBios.java"
  "$project_dir/app/src/main/java/com/netmap/android/Ipp.java"
  "$project_dir/app/src/main/java/com/netmap/android/HttpReply.java"
  "$project_dir/app/src/main/java/com/netmap/android/Smb.java"
  "$project_dir/app/src/main/java/com/netmap/android/SsdpDiscovery.java"
  "$project_dir/app/src/main/java/com/netmap/android/ProbeContext.java"
  "$project_dir/app/src/main/java/com/netmap/android/IdentificationStatus.java"
  "$project_dir/app/src/main/java/com/netmap/android/"*Probe.java
  "$project_dir/app/src/main/java/com/netmap/android/NmapRunner.java"
  "$project_dir/app/src/main/java/com/netmap/android/NmapXmlParser.java"
  "$project_dir/tests/Ipv6CollectionTests.java"
  "$project_dir/tests/ScannerTests.java"
  "$project_dir/tests/IdentificationTests.java"
)
javac -d "$classes_dir" "${sources[@]}"
java -cp "$classes_dir" com.netmap.android.ScannerTests
java -cp "$classes_dir" com.netmap.android.IdentificationTests

java -cp "$classes_dir" com.netmap.android.Ipv6CollectionTests
