#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NETMAP_DEBUG_KEYSTORE="${NETMAP_DEBUG_KEYSTORE:-$project_dir/.signing/netmap-debug.keystore}"
source "$project_dir/tools/apk-identity.sh"
verify_update_keystore
cd "$project_dir"
bash gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug "-PsideBySideInstall=$update_parallel_install" "$@"
bash tools/verify-update-apk.sh app/build/outputs/apk/debug/app-debug.apk
