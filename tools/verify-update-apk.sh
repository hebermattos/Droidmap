#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/apk-identity.sh"
apk="${1:?Usage: verify-update-apk.sh APK}"
sdk_tools="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}/build-tools/35.0.0"
test -x "$sdk_tools/aapt"
test -x "$sdk_tools/apksigner"
badging="$("$sdk_tools/aapt" dump badging "$apk")"
actual_package="$(sed -n "s/^package: name='\([^']*\)'.*/\1/p" <<< "$badging")"
if [[ "$actual_package" != "$update_package" ]]; then
  echo "Unexpected APK package: $actual_package; expected $update_package" >&2
  exit 1
fi
signatures="$("$sdk_tools/apksigner" verify --verbose --print-certs "$apk")"
actual_certificate="$(sed -n 's/^Signer #[0-9][0-9]* certificate SHA-256 digest: //p' <<< "$signatures" | tr '[:upper:]' '[:lower:]')"
if [[ "$actual_certificate" != "$update_certificate" ]]; then
  echo "APK signing certificate mismatch for $update_package" >&2
  exit 1
fi
echo "Verified update package $update_package and pinned signing certificate"
