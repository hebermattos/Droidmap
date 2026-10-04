#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
classes_dir="$(mktemp -d)"
trap 'rm -rf "$classes_dir"' EXIT
javac -d "$classes_dir" "$project_dir/app/src/main/java/com/netmap/android/ScanPlan.java" "$project_dir/app/src/main/java/com/netmap/android/TcpScanner.java" "$project_dir/app/src/main/java/com/netmap/android/AdaptivePolicy.java" "$project_dir/app/src/main/java/com/netmap/android/DeviceEvidence.java" "$project_dir/app/src/main/java/com/netmap/android/DeviceIdentifier.java" "$project_dir/app/src/main/java/com/netmap/android/NetBios.java" "$project_dir/app/src/main/java/com/netmap/android/Ipp.java" "$project_dir/app/src/main/java/com/netmap/android/HttpReply.java" "$project_dir/tests/ScannerTests.java" "$project_dir/tests/IdentificationTests.java"
java -cp "$classes_dir" com.netmap.android.ScannerTests
java -cp "$classes_dir" com.netmap.android.IdentificationTests
