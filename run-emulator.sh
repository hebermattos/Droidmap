#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sdk_dir="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$sdk_dir" ]]; then
  echo 'Set ANDROID_HOME to the Android SDK directory shown in Android Studio.' >&2
  exit 1
fi
adb="$sdk_dir/platform-tools/adb"
emulator="$sdk_dir/emulator/emulator"
if [[ ! -x "$adb" || ! -x "$emulator" ]]; then
  echo 'Install Android SDK Platform-Tools and Android Emulator using SDK Manager.' >&2
  exit 1
fi
if [[ ${1:-} == --list ]]; then
  exec "$emulator" -list-avds
fi
avd="${1:-}"
if [[ -z "$avd" ]] || ! "$emulator" -list-avds | tr -d '\r' | grep -Fxq -- "$avd"; then
  echo 'Usage: bash run-emulator.sh AVD_NAME [EMULATOR_PORT]' >&2
  "$emulator" -list-avds
  exit 1
fi
port="${2:-5554}"
if [[ ! "$port" =~ ^[0-9]{4}$ ]] || (( port < 5554 || port > 5682 || port % 2 != 0 )); then
  echo 'EMULATOR_PORT must be an even number between 5554 and 5682.' >&2
  exit 1
fi
# The existing build script verifies the original signing certificate.
bash "$project_dir/build-apk.sh" --no-daemon
serial="emulator-$port"
if "$adb" -s "$serial" get-state >/dev/null 2>&1; then
  running_avd="$("$adb" -s "$serial" emu avd name | tr -d '\r' | head -n 1)"
  [[ "$running_avd" == "$avd" ]] || { echo "Port $port belongs to another AVD." >&2; exit 1; }
else
  "$emulator" -avd "$avd" -port "$port" >"${TMPDIR:-/tmp}/droidmap-emulator-$port.log" 2>&1 &
fi
deadline=$((SECONDS + 240))
until [[ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == 1 ]]; do
  if (( SECONDS >= deadline )); then
    echo "Emulator boot timed out. Check ${TMPDIR:-/tmp}/droidmap-emulator-$port.log" >&2
    exit 1
  fi
  sleep 2
done
"$adb" -s "$serial" install -r "$project_dir/app/build/outputs/apk/debug/app-debug.apk"
"$adb" -s "$serial" shell am start -W -n com.netmap.android.dns/com.netmap.android.MainActivity
