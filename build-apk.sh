#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NETMAP_DEBUG_KEYSTORE="${NETMAP_DEBUG_KEYSTORE:-$project_dir/.signing/netmap-debug.keystore}"
if [[ ! -f "$NETMAP_DEBUG_KEYSTORE" ]]; then
  echo 'Restore your saved Netmap debug keystore to .signing/netmap-debug.keystore before building.' >&2
  exit 1
fi
expected_certificate='82a648c2bc78d4d22d159b77864b1b60f3540a0a85b2236cafd5d3f7a8021ef2'
actual_certificate="$(keytool -exportcert -keystore "$NETMAP_DEBUG_KEYSTORE" -storepass android -alias androiddebugkey | sha256sum | cut -d ' ' -f 1)"
if [[ "$actual_certificate" != "$expected_certificate" ]]; then
  echo 'This key does not match the delivered Netmap Lite DNS APK. Restore the original signing backup.' >&2
  exit 1
fi
cd "$project_dir"
bash gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug -PsideBySideInstall=true "$@"
